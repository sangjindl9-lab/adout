package kr.eumsoft.securitypro.ui.util

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

fun formatDateTime(millis: Long?): String {
    if (millis == null || millis <= 0) return "-"
    val format = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault())
    return format.format(Date(millis))
}

fun formatDate(millis: Long?): String {
    if (millis == null || millis <= 0) return "-"
    val format = SimpleDateFormat("yyyy-MM-dd", Locale.getDefault())
    return format.format(Date(millis))
}

fun formatNumber(value: Long): String = String.format(Locale.getDefault(), "%,d", value)

fun formatNumber(value: Int): String = formatNumber(value.toLong())

fun startOfToday(now: Long = System.currentTimeMillis()): Long {
    val calendar = java.util.Calendar.getInstance()
    calendar.timeInMillis = now
    calendar.set(java.util.Calendar.HOUR_OF_DAY, 0)
    calendar.set(java.util.Calendar.MINUTE, 0)
    calendar.set(java.util.Calendar.SECOND, 0)
    calendar.set(java.util.Calendar.MILLISECOND, 0)
    return calendar.timeInMillis
}
