package io.ironmesh.android.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

@Composable
fun SectionCard(
    title: String,
    modifier: Modifier = Modifier,
    supportingText: String? = null,
    content: @Composable () -> Unit,
) {
    Card(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp),
        shape = RoundedCornerShape(24.dp),
    ) {
        Column(
            modifier = Modifier.padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(title, style = MaterialTheme.typography.titleMedium)
                supportingText
                    ?.takeIf { it.isNotBlank() }
                    ?.let {
                        Text(
                            text = it,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
            }
            content()
        }
    }
}

@Composable
fun StatusHeroCard(
    title: String,
    tone: HeroTone,
    subtitle: String,
    modifier: Modifier = Modifier,
    actions: @Composable (() -> Unit)? = null,
) {
    val colors = when (tone) {
        HeroTone.Good -> MaterialTheme.colorScheme.primary to MaterialTheme.colorScheme.onPrimary
        HeroTone.Warning -> Color(0xFF9A5A00) to Color.White
        HeroTone.Error -> Color(0xFF8C2F24) to Color.White
        HeroTone.Neutral -> MaterialTheme.colorScheme.surfaceVariant to MaterialTheme.colorScheme.onSurface
    }
    Card(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = colors.first),
        shape = RoundedCornerShape(28.dp),
    ) {
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.headlineSmall,
                color = colors.second,
            )
            Text(
                text = subtitle,
                style = MaterialTheme.typography.bodyLarge,
                color = colors.second.copy(alpha = 0.92f),
            )
            if (actions != null) {
                actions()
            }
        }
    }
}

enum class HeroTone {
    Good,
    Warning,
    Error,
    Neutral,
}

@Composable
fun MetricPill(
    label: String,
    value: String,
    modifier: Modifier = Modifier,
) {
    Surface(
        modifier = modifier,
        color = MaterialTheme.colorScheme.surfaceVariant,
        shape = RoundedCornerShape(22.dp),
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            Text(
                text = value,
                style = MaterialTheme.typography.titleMedium,
            )
            Text(
                text = label,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
fun EmptyStateCard(
    title: String,
    body: String,
    actionLabel: String,
    onAction: () -> Unit,
    modifier: Modifier = Modifier,
) {
    SectionCard(
        title = title,
        modifier = modifier,
        supportingText = body,
    ) {
        Button(onClick = onAction) {
            Text(actionLabel)
        }
    }
}

@Composable
fun PermissionExplainerCard(
    title: String,
    body: String,
    status: String,
    actionLabel: String? = null,
    onAction: (() -> Unit)? = null,
) {
    SectionCard(
        title = title,
        supportingText = body,
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = status,
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (actionLabel != null && onAction != null) {
                OutlinedButton(onClick = onAction) {
                    Text(actionLabel)
                }
            }
        }
    }
}

@Composable
fun TimelineDot(
    color: Color,
    modifier: Modifier = Modifier,
) {
    Box(
        modifier = modifier
            .background(color = color, shape = CircleShape),
    )
}
