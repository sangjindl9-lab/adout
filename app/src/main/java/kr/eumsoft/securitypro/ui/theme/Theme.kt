package kr.eumsoft.securitypro.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

private val LightColors = lightColorScheme(
    primary = BrandBlue,
    onPrimary = androidx.compose.ui.graphics.Color.White,
    primaryContainer = androidx.compose.ui.graphics.Color(0xFFDCE6FB),
    onPrimaryContainer = BrandBlueDark,
    secondary = SafeGreen,
    onSecondary = androidx.compose.ui.graphics.Color.White,
    secondaryContainer = androidx.compose.ui.graphics.Color(0xFFD7F0E3),
    onSecondaryContainer = androidx.compose.ui.graphics.Color(0xFF06402A),
    tertiary = WarnAmber,
    error = DangerRed,
    background = androidx.compose.ui.graphics.Color(0xFFF7F9FC),
    surface = androidx.compose.ui.graphics.Color(0xFFFFFFFF),
    surfaceVariant = androidx.compose.ui.graphics.Color(0xFFE5EAF2),
    onSurface = androidx.compose.ui.graphics.Color(0xFF1A1F27),
    onSurfaceVariant = androidx.compose.ui.graphics.Color(0xFF44505F),
)

private val DarkColors = darkColorScheme(
    primary = BrandBlueLight,
    onPrimary = androidx.compose.ui.graphics.Color(0xFF06152E),
    primaryContainer = BrandBlueDark,
    onPrimaryContainer = androidx.compose.ui.graphics.Color(0xFFDCE6FB),
    secondary = SafeGreenLight,
    onSecondary = androidx.compose.ui.graphics.Color(0xFF06251A),
    secondaryContainer = androidx.compose.ui.graphics.Color(0xFF0B4A31),
    onSecondaryContainer = androidx.compose.ui.graphics.Color(0xFFD7F0E3),
    tertiary = WarnAmberLight,
    error = DangerRedLight,
    background = androidx.compose.ui.graphics.Color(0xFF0F141B),
    surface = androidx.compose.ui.graphics.Color(0xFF161D26),
    surfaceVariant = androidx.compose.ui.graphics.Color(0xFF2A3441),
    onSurface = androidx.compose.ui.graphics.Color(0xFFE7ECF3),
    onSurfaceVariant = androidx.compose.ui.graphics.Color(0xFFB9C4D2),
)

/** 읽기 쉬운 큰 글자 중심 타이포그래피(10대~70대 사용자 고려). */
val EumTypography = Typography(
    displaySmall = TextStyle(fontSize = 34.sp, lineHeight = 42.sp, fontWeight = FontWeight.Bold),
    headlineMedium = TextStyle(fontSize = 28.sp, lineHeight = 36.sp, fontWeight = FontWeight.Bold),
    headlineSmall = TextStyle(fontSize = 24.sp, lineHeight = 32.sp, fontWeight = FontWeight.SemiBold),
    titleLarge = TextStyle(fontSize = 21.sp, lineHeight = 28.sp, fontWeight = FontWeight.SemiBold),
    titleMedium = TextStyle(fontSize = 18.sp, lineHeight = 24.sp, fontWeight = FontWeight.SemiBold),
    bodyLarge = TextStyle(fontSize = 17.sp, lineHeight = 26.sp),
    bodyMedium = TextStyle(fontSize = 15.sp, lineHeight = 23.sp),
    labelLarge = TextStyle(fontSize = 16.sp, lineHeight = 22.sp, fontWeight = FontWeight.SemiBold),
)

@Composable
fun EumTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = if (darkTheme) DarkColors else LightColors,
        typography = EumTypography,
        content = content,
    )
}
