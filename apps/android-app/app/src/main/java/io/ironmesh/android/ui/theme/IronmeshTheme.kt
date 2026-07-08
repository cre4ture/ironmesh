package io.ironmesh.android.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.material3.Typography
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

private val Ink = Color(0xFF112523)
private val DeepTeal = Color(0xFF0D6B5C)
private val Teal = Color(0xFF14B8A6)
private val Mint = Color(0xFF74E4C8)
private val Mist = Color(0xFFF4FBF9)
private val Slate = Color(0xFF5E716D)
private val WarmSurface = Color(0xFFE8F4F1)
private val RustError = Color(0xFFB84434)
private val DarkSurface = Color(0xFF101816)
private val DarkSurfaceRaised = Color(0xFF16211E)

private val IronmeshLightColors = lightColorScheme(
    primary = DeepTeal,
    onPrimary = Color.White,
    primaryContainer = Mint,
    onPrimaryContainer = Ink,
    secondary = Teal,
    onSecondary = Ink,
    secondaryContainer = WarmSurface,
    onSecondaryContainer = Ink,
    tertiary = Color(0xFF3D645D),
    onTertiary = Color.White,
    background = Mist,
    onBackground = Ink,
    surface = Color.White,
    onSurface = Ink,
    surfaceVariant = Color(0xFFE2EFEB),
    onSurfaceVariant = Slate,
    outline = Color(0xFFB0C4BE),
    outlineVariant = Color(0xFFD0E0DB),
    error = RustError,
    onError = Color.White,
)

private val IronmeshDarkColors = darkColorScheme(
    primary = Mint,
    onPrimary = Ink,
    primaryContainer = DeepTeal,
    onPrimaryContainer = Color(0xFFE6FFF8),
    secondary = Teal,
    onSecondary = Ink,
    secondaryContainer = Color(0xFF1B332F),
    onSecondaryContainer = Color(0xFFD5FFF5),
    tertiary = Color(0xFF8BCBC0),
    onTertiary = Ink,
    background = DarkSurface,
    onBackground = Color(0xFFE5F5F0),
    surface = DarkSurface,
    onSurface = Color(0xFFE5F5F0),
    surfaceVariant = DarkSurfaceRaised,
    onSurfaceVariant = Color(0xFFAAC1BB),
    outline = Color(0xFF6F8B84),
    outlineVariant = Color(0xFF2A3B37),
    error = Color(0xFFFF9E8F),
    onError = Color(0xFF5D130D),
)

private val AppTypography = Typography(
    headlineLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Bold,
        fontSize = 32.sp,
        lineHeight = 36.sp,
    ),
    headlineMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Bold,
        fontSize = 28.sp,
        lineHeight = 32.sp,
    ),
    headlineSmall = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Bold,
        fontSize = 24.sp,
        lineHeight = 28.sp,
    ),
    titleLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 22.sp,
        lineHeight = 28.sp,
    ),
    titleMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 18.sp,
        lineHeight = 24.sp,
    ),
    titleSmall = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 15.sp,
        lineHeight = 20.sp,
    ),
    bodyLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Normal,
        fontSize = 16.sp,
        lineHeight = 24.sp,
    ),
    bodyMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Normal,
        fontSize = 14.sp,
        lineHeight = 20.sp,
    ),
    bodySmall = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Normal,
        fontSize = 12.sp,
        lineHeight = 18.sp,
    ),
    labelLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 14.sp,
        lineHeight = 20.sp,
    ),
)

@Composable
fun IronmeshTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = if (darkTheme) IronmeshDarkColors else IronmeshLightColors,
        typography = AppTypography,
        content = content,
    )
}
