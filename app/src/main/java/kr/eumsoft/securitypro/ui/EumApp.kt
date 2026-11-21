package kr.eumsoft.securitypro.ui

import android.content.res.Configuration
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.List
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import java.util.Locale
import kr.eumsoft.securitypro.R
import kr.eumsoft.securitypro.data.prefs.ThemeMode
import kr.eumsoft.securitypro.ui.screens.AdBlockScreen
import kr.eumsoft.securitypro.ui.screens.DatabaseScreen
import kr.eumsoft.securitypro.ui.screens.HomeScreen
import kr.eumsoft.securitypro.ui.screens.ResultScreen
import kr.eumsoft.securitypro.ui.screens.ScanScreen
import kr.eumsoft.securitypro.ui.screens.SettingsScreen
import kr.eumsoft.securitypro.ui.theme.EumTheme

private data class Destination(
    val route: String,
    val labelRes: Int,
    val descriptionRes: Int,
    val icon: androidx.compose.ui.graphics.vector.ImageVector,
)

private val destinations = listOf(
    Destination("home", R.string.nav_home, R.string.nav_home_desc, Icons.Filled.Home),
    Destination("adblock", R.string.nav_adblock, R.string.nav_adblock_desc, Icons.Filled.Lock),
    Destination("scan", R.string.nav_scan, R.string.nav_scan_desc, Icons.Filled.Search),
    Destination("db", R.string.nav_db, R.string.nav_db_desc, Icons.Filled.List),
    Destination("settings", R.string.nav_settings, R.string.nav_settings_desc, Icons.Filled.Settings),
)

@Composable
fun EumApp(rootViewModel: RootViewModel = hiltViewModel()) {
    val settingsState by rootViewModel.state.collectAsStateWithLifecycle()
    val themeMode = settingsState.settings.themeMode
    val darkTheme = when (themeMode) {
        ThemeMode.SYSTEM -> isSystemInDarkTheme()
        ThemeMode.LIGHT -> false
        ThemeMode.DARK -> true
    }
    val context = LocalContext.current
    val language = settingsState.settings.language
    val localizedContext = remember(language, context) {
        if (language == "system") {
            context
        } else {
            runCatching {
                val locale = Locale.forLanguageTag(language)
                val configuration = Configuration(context.resources.configuration)
                configuration.setLocale(locale)
                context.createConfigurationContext(configuration)
            }.getOrDefault(context)
        }
    }

    CompositionLocalProvider(
        LocalContext provides localizedContext,
        LocalConfiguration provides localizedContext.resources.configuration,
    ) {
        EumTheme(darkTheme = darkTheme) {
            EumNavigation()
        }
    }
}

@Composable
private fun EumNavigation() {
    val navController = rememberNavController()
    val backStackEntry by navController.currentBackStackEntryAsState()
    val currentRoute = backStackEntry?.destination?.route

    BoxWithConstraints(modifier = Modifier.fillMaxSize()) {
        val expanded = maxWidth >= 840.dp
        if (expanded) {
            androidx.compose.foundation.layout.Row {
                NavigationRail {
                    destinations.forEach { destination ->
                        NavigationRailItem(
                            selected = currentRoute?.startsWith(destination.route) == true,
                            onClick = { navigate(navController, destination.route) },
                            icon = {
                                Icon(
                                    imageVector = destination.icon,
                                    contentDescription = stringResource(destination.descriptionRes),
                                )
                            },
                            label = { Text(stringResource(destination.labelRes)) },
                        )
                    }
                }
                AppNavHost(navController, Modifier.weight(1f))
            }
        } else {
            Scaffold(
                bottomBar = {
                    NavigationBar {
                        destinations.forEach { destination ->
                            NavigationBarItem(
                                selected = currentRoute?.startsWith(destination.route) == true,
                                onClick = { navigate(navController, destination.route) },
                                icon = {
                                    Icon(
                                        imageVector = destination.icon,
                                        contentDescription = stringResource(destination.descriptionRes),
                                    )
                                },
                                label = { Text(stringResource(destination.labelRes)) },
                            )
                        }
                    }
                },
            ) { padding ->
                AppNavHost(navController, Modifier.padding(padding))
            }
        }
    }
}

private fun navigate(
    navController: androidx.navigation.NavHostController,
    route: String,
) {
    navController.navigate(route) {
        popUpTo(navController.graph.findStartDestination().id) { saveState = true }
        launchSingleTop = true
        restoreState = true
    }
}

@Composable
private fun AppNavHost(
    navController: androidx.navigation.NavHostController,
    modifier: Modifier = Modifier,
) {
    NavHost(
        navController = navController,
        startDestination = "home",
        modifier = modifier.fillMaxSize(),
    ) {
        composable("home") {
            HomeScreen(
                onOpenAdBlock = { navController.navigate("adblock") },
                onOpenResult = { sessionId ->
                    navController.navigate("result/$sessionId")
                },
            )
        }
        composable("adblock") { AdBlockScreen() }
        composable("scan") {
            ScanScreen(
                onOpenResult = { sessionId -> navController.navigate("result/$sessionId") },
            )
        }
        composable("db") { DatabaseScreen() }
        composable("settings") { SettingsScreen() }
        composable("result/{sessionId}") { entry ->
            val sessionId = entry.arguments?.getString("sessionId")?.toLongOrNull() ?: -1L
            ResultScreen(sessionId = sessionId, onBack = { navController.popBackStack() })
        }
    }
}

@Composable
fun ShieldIcon(modifier: Modifier = Modifier) {
    Icon(
        imageVector = Icons.Filled.CheckCircle,
        contentDescription = stringResource(R.string.cd_status_shield),
        modifier = modifier,
    )
}
