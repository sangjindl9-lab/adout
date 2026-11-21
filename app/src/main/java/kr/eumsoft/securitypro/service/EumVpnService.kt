package kr.eumsoft.securitypro.service

import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.ServiceCompat
import dagger.hilt.android.AndroidEntryPoint
import java.io.FileInputStream
import java.io.IOException
import javax.inject.Inject
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withLock
import kr.eumsoft.securitypro.core.dns.BlockResponseMode
import kr.eumsoft.securitypro.core.net.DnsEvent
import kr.eumsoft.securitypro.core.net.DnsResponseCache
import kr.eumsoft.securitypro.core.net.DnsTunHandler
import kr.eumsoft.securitypro.core.net.DnsUpstream
import kr.eumsoft.securitypro.data.db.dao.AdFilterDao
import kr.eumsoft.securitypro.data.db.dao.VpnSessionDao
import kr.eumsoft.securitypro.data.db.entity.VpnSessionEntity
import kr.eumsoft.securitypro.data.prefs.AppSettings
import kr.eumsoft.securitypro.data.prefs.SettingsRepository
import kr.eumsoft.securitypro.data.repo.AdFilterRepository
import kr.eumsoft.securitypro.service.net.UpstreamFactory

/**
 * 로컬 DNS 광고 차단 VPN.
 *
 * 앱의 DNS 질의만 가상 DNS 서버(10.111.222.2)로 끌어와 필터링한다. 그 외 트래픽은
 * 라우팅하지 않으므로 일반 인터넷 통신은 VPN 밖으로 그대로 나간다(DNS 전용 설계).
 */
@AndroidEntryPoint
class EumVpnService : VpnService() {

    @Inject
    lateinit var filterRepository: AdFilterRepository

    @Inject
    lateinit var settingsRepository: SettingsRepository

    @Inject
    lateinit var vpnSessionDao: VpnSessionDao

    @Inject
    lateinit var adFilterDao: AdFilterDao

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var tunFd: ParcelFileDescriptor? = null
    private var loopJob: Job? = null
    private var notificationJob: Job? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var upstream: DnsUpstream? = null
    private var sessionId: Long = -1L
    private var settings: AppSettings = AppSettings()
    private val writeMutex = Mutex()
    private var tunOutput: java.io.FileOutputStream? = null
    private val eventChannel = Channel<DnsEvent>(capacity = 1024)
    private val cache = DnsResponseCache(maxEntries = 512)

    @Volatile
    private var stopped = false

    override fun onCreate() {
        super.onCreate()
        Notifications.ensureChannels(this)
        scope.launch {
            settingsRepository.settings.collect { updated ->
                settings = updated
                VpnStateHolder.update { it.copy(paused = updated.isPaused(System.currentTimeMillis())) }
            }
        }
        scope.launch { persistEvents() }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> stopVpn("USER_STOP")
            ACTION_START -> startVpn()
            else -> if (!VpnStateHolder.state.value.running) startVpn()
        }
        return Service.START_NOT_STICKY
    }

    private fun startVpn() {
        if (VpnStateHolder.state.value.running || VpnStateHolder.state.value.starting) return
        VpnStateHolder.update { it.copy(starting = true, needsPermission = false, message = null) }
        if (prepare(this) != null) {
            VpnStateHolder.update {
                it.copy(starting = false, needsPermission = true, message = "VPN 사용 동의가 필요합니다.")
            }
            stopSelf()
            return
        }
        scope.launch {
            runCatching {
                settings = settingsRepository.settings.first()
                filterRepository.reload()
                establishTunnel()
            }.onFailure { e ->
                VpnStateHolder.update {
                    it.copy(starting = false, running = false, message = "VPN 시작 실패: ${e.message}")
                }
                stopVpn("ERROR")
            }
        }
    }

    private suspend fun establishTunnel() {
        val builder = Builder()
            .setSession("EUM SECURITY PRO")
            .setMtu(1500)
            .addAddress(VPN_ADDRESS_V4, 32)
            .addAddress(VPN_ADDRESS_V6, 128)
            .addDnsServer(DNS_ADDRESS_V4)
            .addDnsServer(DNS_ADDRESS_V6)
            .addRoute(DNS_ADDRESS_V4, 32)
            .addRoute(DNS_ADDRESS_V6, 128)

        // 앱이 DNS 서버를 직접 지정하는 경우도 잡기 위해 주요 리졸버로 가는 경로를 추가한다.
        COMMON_RESOLVERS.forEach { builder.addRoute(it, 32) }

        settings.excludedPackages.forEach { packageName ->
            if (packageName == this.packageName) return@forEach
            runCatching { builder.addDisallowedApplication(packageName) }
        }
        builder.setBlocking(true)

        val fd = builder.establish()
        if (fd == null) {
            VpnStateHolder.update { it.copy(starting = false, message = "VPN 인터페이스를 만들 수 없습니다.") }
            stopSelf()
            return
        }
        tunFd = fd
        tunOutput = java.io.FileOutputStream(fd.fileDescriptor)
        val startedAt = System.currentTimeMillis()
        sessionId = vpnSessionDao.startSession(VpnSessionEntity(startedAt = startedAt)).toLong()

        VpnStateHolder.update {
            it.copy(
                running = true,
                starting = false,
                startedAt = startedAt,
                queries = 0,
                blocked = 0,
                upstream = upstreamDescription(),
                needsPermission = false,
                message = null,
            )
        }
        startForegroundNotification()
        registerNetworkCallback()
        startLoop(fd)
        startNotificationUpdates()
        clearStaleEvents()
    }

    private fun upstreamDescription(): String = when (settings.dnsMode) {
        kr.eumsoft.securitypro.data.prefs.DnsMode.SYSTEM -> "시스템 DNS"
        kr.eumsoft.securitypro.data.prefs.DnsMode.DOH -> "DoH (${settings.dnsProvider})"
        kr.eumsoft.securitypro.data.prefs.DnsMode.DOT -> "DoT (${settings.dnsProvider})"
    }

    private fun startLoop(fd: ParcelFileDescriptor) {
        val handler = DnsTunHandler(
            engineProvider = { filterRepository.engine() },
            blockingEnabled = {
                val now = System.currentTimeMillis()
                settings.adBlockEnabled && !settings.isPaused(now)
            },
            responseMode = { settings.blockResponseMode },
            upstream = instantiateUpstream(),
            cache = cache,
            onEvent = { event -> onDnsEvent(event) },
        )
        val semaphore = Semaphore(12)
        loopJob = scope.launch {
            FileInputStream(fd.fileDescriptor).use { input ->
                val buffer = ByteArray(32768)
                while (isActive) {
                    val length = try {
                        input.read(buffer)
                    } catch (_: IOException) {
                        break
                    }
                    if (length <= 0) continue
                    if (length < 20) continue
                    val packet = buffer.copyOf(length)
                    semaphore.acquire()
                    scope.launch {
                        try {
                            handler.handle(packet, length)?.let { response -> writeToTun(response) }
                        } finally {
                            semaphore.release()
                        }
                    }
                }
            }
        }
    }

    private fun instantiateUpstream(): DnsUpstream? = runCatching {
        UpstreamFactory.create(
            mode = settings.dnsMode,
            provider = settings.dnsProvider,
            customHost = settings.customDnsName,
            protector = object : kr.eumsoft.securitypro.service.net.SocketProtector {
                override fun protect(socket: java.net.Socket): Boolean =
                    this@EumVpnService.protect(socket)

                override fun protect(socket: java.net.DatagramSocket): Boolean =
                    this@EumVpnService.protect(socket)
            },
            connectivity = getSystemService(ConnectivityManager::class.java),
        )
    }.onFailure {
        VpnStateHolder.update { state -> state.copy(message = "업스트림 DNS 초기화 실패: ${it.message}") }
    }.getOrNull().also { upstream = it }

    private suspend fun writeToTun(packet: ByteArray) {
        val output = tunOutput ?: return
        writeMutex.withLock {
            runCatching {
                output.write(packet)
                output.flush()
            }
        }
    }

    private fun onDnsEvent(event: DnsEvent) {
        VpnStateHolder.recordQuery(event.blocked, event.domain)
        if (event.blocked) {
            eventChannel.trySend(event)
        }
    }

    /** 차단 이벤트를 모아 DB 에 기록한다(과도한 쓰기 방지). */
    private suspend fun persistEvents() {
        val batch = ArrayList<DnsEvent>(64)
        while (true) {
            val first = try {
                eventChannel.receive()
            } catch (_: Exception) {
                break
            }
            batch += first
            while (batch.size < 100) {
                val next = eventChannel.tryReceive().getOrNull() ?: break
                batch += next
            }
            try {
                adFilterDao.insertEvents(
                    batch.map { event ->
                        kr.eumsoft.securitypro.data.db.entity.BlockedDnsEventEntity(
                            domain = event.domain,
                            category = event.category ?: "UNKNOWN",
                            sourceId = event.sourceId,
                            ruleMatched = event.matchedRule,
                            action = "BLOCKED",
                            blockedAt = event.at,
                        )
                    }
                )
            } catch (_: Exception) {
                // 기록 실패는 DNS 응답을 막지 않는다.
            }
            batch.clear()
        }
    }

    private suspend fun clearStaleEvents() {
        runCatching {
            val retention = settings.logRetentionDays.coerceIn(1, 365)
            adFilterDao.pruneEventsBefore(System.currentTimeMillis() - retention * 86_400_000L)
        }
    }

    private fun startForegroundNotification() {
        val state = VpnStateHolder.state.value
        val notification = Notifications.vpnNotification(this, state)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            ServiceCompat.startForeground(
                this,
                Notifications.VPN_NOTIFICATION_ID,
                notification,
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
                } else {
                    0
                },
            )
        } else {
            startForeground(Notifications.VPN_NOTIFICATION_ID, notification)
        }
    }

    private fun startNotificationUpdates() {
        notificationJob?.cancel()
        notificationJob = scope.launch {
            while (isActive) {
                delay(5_000)
                val manager = getSystemService(android.app.NotificationManager::class.java)
                runCatching {
                    manager?.notify(
                        Notifications.VPN_NOTIFICATION_ID,
                        Notifications.vpnNotification(this@EumVpnService, VpnStateHolder.state.value),
                    )
                }
            }
        }
    }

    private fun registerNetworkCallback() {
        val manager = getSystemService(ConnectivityManager::class.java) ?: return
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                // 네트워크가 바뀌면 업스트림을 새로 만든다(구 소켓은 GC 로 회수).
                runCatching { upstream?.close() }
                upstream = instantiateUpstream()
            }

            override fun onLost(network: Network) {
                VpnStateHolder.update { it.copy(message = "네트워크 변경 감지") }
            }
        }
        networkCallback = callback
        runCatching { manager.registerDefaultNetworkCallback(callback) }
    }

    private fun stopVpn(reason: String) {
        if (stopped) return
        stopped = true
        runCatching { networkCallback?.let { getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(it) } }
        networkCallback = null
        notificationJob?.cancel()
        loopJob?.cancel()
        runCatching { tunOutput?.close() }
        tunOutput = null
        runCatching { tunFd?.close() }
        tunFd = null
        runCatching { upstream?.close() }
        upstream = null

        val state = VpnStateHolder.state.value
        val id = sessionId
        if (id > 0) {
            runBlocking {
                runCatching {
                    vpnSessionDao.endSession(
                        id = id,
                        endedAt = System.currentTimeMillis(),
                        queries = state.queries,
                        blocked = state.blocked,
                        bytesIn = 0,
                        bytesOut = 0,
                        reason = reason,
                    )
                }
            }
        }
        sessionId = -1L
        VpnStateHolder.reset()
        runCatching {
            ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        }
        stopSelf()
    }

    override fun onRevoke() {
        stopVpn("REVOKED")
        super.onRevoke()
    }

    override fun onDestroy() {
        if (!stopped) {
            stopped = true
            notificationJob?.cancel()
            loopJob?.cancel()
            runCatching { tunOutput?.close() }
            runCatching { tunFd?.close() }
            runCatching { upstream?.close() }
        }
        eventChannel.close()
        scope.cancel()
        super.onDestroy()
    }

    companion object {
        const val ACTION_START = "kr.eumsoft.securitypro.action.START"
        const val ACTION_STOP = "kr.eumsoft.securitypro.action.STOP"
        const val VPN_ADDRESS_V4 = "10.111.222.1"
        const val VPN_ADDRESS_V6 = "fd00:1:0:e222::1"
        const val DNS_ADDRESS_V4 = "10.111.222.2"
        const val DNS_ADDRESS_V6 = "fd00:1:0:e222::2"

        /** 앱이 하드코딩해 쓰는 대표 리졸버. 이 주소로 가는 DNS 도 터널 안에서 처리한다. */
        val COMMON_RESOLVERS = listOf(
            "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
            "208.67.222.222", "208.67.220.220", "168.126.63.1", "168.126.63.2",
            "114.114.114.114", "223.5.5.5", "94.140.14.14", "94.140.15.15",
        )
    }
}
