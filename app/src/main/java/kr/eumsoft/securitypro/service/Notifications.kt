package kr.eumsoft.securitypro.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import kr.eumsoft.securitypro.R
import kr.eumsoft.securitypro.ui.MainActivity

/** VPN 상태/검사 알림. 채널은 한 번만 만든다. */
object Notifications {

    const val CHANNEL_VPN = "vpn_status"
    const val CHANNEL_SCAN = "scan_results"
    const val CHANNEL_UPDATE = "db_update"
    const val VPN_NOTIFICATION_ID = 1001

    fun ensureChannels(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        val vpn = NotificationChannel(
            CHANNEL_VPN,
            context.getString(R.string.notif_channel_vpn),
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = context.getString(R.string.notif_channel_vpn_desc)
            setShowBadge(false)
        }
        val scan = NotificationChannel(
            CHANNEL_SCAN,
            context.getString(R.string.notif_channel_scan),
            NotificationManager.IMPORTANCE_DEFAULT,
        ).apply { description = context.getString(R.string.notif_channel_scan_desc) }
        val update = NotificationChannel(
            CHANNEL_UPDATE,
            context.getString(R.string.notif_channel_update),
            NotificationManager.IMPORTANCE_LOW,
        ).apply { description = context.getString(R.string.notif_channel_update_desc) }
        manager.createNotificationChannels(listOf(vpn, scan, update))
    }

    fun vpnNotification(context: Context, state: VpnState): Notification {
        val openIntent = PendingIntent.getActivity(
            context,
            0,
            Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val stopIntent = PendingIntent.getService(
            context,
            1,
            Intent(context, EumVpnService::class.java).setAction(EumVpnService.ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val title = if (state.paused) {
            context.getString(R.string.notif_vpn_paused)
        } else {
            context.getString(R.string.notif_vpn_running)
        }
        val text = context.getString(
            R.string.notif_vpn_counters,
            state.blocked,
            state.queries,
            state.upstream.ifEmpty { context.getString(R.string.notif_vpn_upstream_default) },
        )
        return NotificationCompat.Builder(context, CHANNEL_VPN)
            .setSmallIcon(R.drawable.ic_stat_shield)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setContentIntent(openIntent)
            .addAction(0, context.getString(R.string.action_stop_vpn), stopIntent)
            .build()
    }

    fun scanFinished(context: Context, title: String, message: String) {
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        val openIntent = PendingIntent.getActivity(
            context,
            2,
            Intent(context, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val notification = NotificationCompat.Builder(context, CHANNEL_SCAN)
            .setSmallIcon(R.drawable.ic_stat_shield)
            .setContentTitle(title)
            .setContentText(message)
            .setStyle(NotificationCompat.BigTextStyle().bigText(message))
            .setAutoCancel(true)
            .setContentIntent(openIntent)
            .build()
        manager.notify(2001, notification)
    }
}
