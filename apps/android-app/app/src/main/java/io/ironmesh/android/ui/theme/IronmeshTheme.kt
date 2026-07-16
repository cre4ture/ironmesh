package io.ironmesh.android.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import kotlin.math.roundToInt

private val Ink = Color(0xFF112523)
private val Mist = Color(0xFFF4FBF9)
private val Slate = Color(0xFF5E716D)
private val WarmSurface = Color(0xFFE8F4F1)
private val WarmOutline = Color(0xFFB0C4BE)
private val WarmOutlineVariant = Color(0xFFD0E0DB)
private val RustError = Color(0xFFB84434)
private val DarkError = Color(0xFFFF9E8F)
private val DarkErrorOn = Color(0xFF5D130D)
private val DarkSurface = Color(0xFF101816)
private val DarkSurfaceRaised = Color(0xFF16211E)

const val DEFAULT_IRONMESH_ACCENT_COLOR_HEX = "#14B8A6"

val IRONMESH_ACCENT_COLOR_SWATCHES = listOf(
    DEFAULT_IRONMESH_ACCENT_COLOR_HEX,
    "#2563EB",
    "#7C3AED",
    "#DB2777",
    "#EA580C",
    "#D4A017",
)

private val DefaultAccentColor = parseColorHex(DEFAULT_IRONMESH_ACCENT_COLOR_HEX)

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

fun normalizeIronmeshAccentColorHex(value: String?): String? {
    val trimmed = value?.trim().orEmpty()
    if (trimmed.isEmpty()) {
        return null
    }

    val withoutHash = trimmed.removePrefix("#")
    val expanded = when (withoutHash.length) {
        3 -> withoutHash.map { "$it$it" }.joinToString("")
        6 -> withoutHash
        else -> return null
    }

    if (!expanded.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) {
        return null
    }

    return "#${expanded.uppercase()}"
}

fun parseIronmeshAccentColorOrDefault(value: String?): Color =
    normalizeIronmeshAccentColorHex(value)
        ?.let(::parseColorHex)
        ?: DefaultAccentColor

fun ironmeshAccentColorToHex(color: Color): String {
    val red = (color.red * 255f).roundToInt().coerceIn(0, 255)
    val green = (color.green * 255f).roundToInt().coerceIn(0, 255)
    val blue = (color.blue * 255f).roundToInt().coerceIn(0, 255)
    return "#%02X%02X%02X".format(red, green, blue)
}

@Composable
fun IronmeshTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    accentColorHex: String = DEFAULT_IRONMESH_ACCENT_COLOR_HEX,
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = createIronmeshColorScheme(
            darkTheme = darkTheme,
            accentColorHex = accentColorHex,
        ),
        typography = AppTypography,
        content = content,
    )
}

private fun createIronmeshColorScheme(
    darkTheme: Boolean,
    accentColorHex: String,
): ColorScheme {
    val accent = parseIronmeshAccentColorOrDefault(accentColorHex)

    return if (darkTheme) {
        val primary = blend(accent, Color.White, 0.34f)
        val primaryContainer = blend(accent, Ink, 0.44f)
        val secondary = blend(accent, Color.White, 0.18f)
        val secondaryContainer = blend(accent, DarkSurface, 0.72f)
        val tertiary = blend(accent, Color.White, 0.28f)

        darkColorScheme(
            primary = primary,
            onPrimary = onColorFor(primary),
            primaryContainer = primaryContainer,
            onPrimaryContainer = onColorFor(primaryContainer),
            secondary = secondary,
            onSecondary = onColorFor(secondary),
            secondaryContainer = secondaryContainer,
            onSecondaryContainer = onColorFor(secondaryContainer),
            tertiary = tertiary,
            onTertiary = onColorFor(tertiary),
            background = DarkSurface,
            onBackground = Color(0xFFE5F5F0),
            surface = DarkSurface,
            onSurface = Color(0xFFE5F5F0),
            surfaceVariant = blend(accent, DarkSurfaceRaised, 0.78f),
            onSurfaceVariant = Color(0xFFAAC1BB),
            outline = blend(accent, Color(0xFF6F8B84), 0.62f),
            outlineVariant = blend(accent, Color(0xFF2A3B37), 0.84f),
            error = DarkError,
            onError = DarkErrorOn,
            errorContainer = blend(DarkError, DarkSurface, 0.58f),
            onErrorContainer = Color(0xFFFFDDD6),
            inversePrimary = blend(accent, Mist, 0.48f),
        )
    } else {
        val primary = blend(accent, Ink, 0.48f)
        val primaryContainer = blend(accent, Color.White, 0.62f)
        val secondary = accent
        val secondaryContainer = blend(accent, Mist, 0.78f)
        val tertiary = blend(accent, Ink, 0.28f)

        lightColorScheme(
            primary = primary,
            onPrimary = onColorFor(primary),
            primaryContainer = primaryContainer,
            onPrimaryContainer = onColorFor(primaryContainer),
            secondary = secondary,
            onSecondary = onColorFor(secondary),
            secondaryContainer = secondaryContainer,
            onSecondaryContainer = onColorFor(secondaryContainer),
            tertiary = tertiary,
            onTertiary = onColorFor(tertiary),
            background = Mist,
            onBackground = Ink,
            surface = Color.White,
            onSurface = Ink,
            surfaceVariant = blend(accent, WarmSurface, 0.82f),
            onSurfaceVariant = Slate,
            outline = blend(accent, WarmOutline, 0.78f),
            outlineVariant = blend(accent, WarmOutlineVariant, 0.82f),
            error = RustError,
            onError = Color.White,
            errorContainer = blend(RustError, Color.White, 0.74f),
            onErrorContainer = Color(0xFF5D130D),
            inversePrimary = blend(accent, Ink, 0.18f),
        )
    }
}

private fun onColorFor(color: Color): Color =
    if (color.luminance() > 0.42f) Ink else Color.White

private fun blend(
    color: Color,
    target: Color,
    amount: Float,
): Color {
    val clampedAmount = amount.coerceIn(0f, 1f)
    return Color(
        red = color.red + (target.red - color.red) * clampedAmount,
        green = color.green + (target.green - color.green) * clampedAmount,
        blue = color.blue + (target.blue - color.blue) * clampedAmount,
        alpha = 1f,
    )
}

private fun parseColorHex(hex: String): Color {
    val normalized = normalizeIronmeshAccentColorHex(hex) ?: DEFAULT_IRONMESH_ACCENT_COLOR_HEX
    return Color(0xFF000000L or normalized.removePrefix("#").toLong(16))
}
