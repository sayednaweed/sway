<?php

namespace Sway\Utils;


class StringUtils
{
    /**
     * Converts a string to title case.
     *
     * @param string $model
     * @return string
     */
    public static function getModelName(string $model): string
    {
        // Generate a unique key for the access token, e.g., access_token:<user_id>
        $firstSlashPos = strpos($model, '\\');
        $secondSlashPos = strpos($model, '\\', $firstSlashPos + 1);

        // Get the part after the second backslash
        $className = substr($model, $secondSlashPos + 1);
        return $className;
    }
    /**
     * Converts a string to title case.
     *
     * @param string $model
     * @return string
     */
    public static function getRedisKey(string $model, string $userId): string
    {
        return $model . ':' . $userId;
    }
    // /**
    //  * Extracts Device name from $userAgent.
    //  *
    //  * @param string $userAgent
    //  * @return string
    //  */
    // public static function extractDeviceInfo($userAgent)
    // {
    //     // Match OS and architecture details
    //     if (preg_match('/\(([^)]+)\)/', $userAgent, $matches)) {
    //         return $matches[1]; // Extract content inside parentheses
    //     }
    //     return "Unknown Device";
    // }
    // /**
    //  * Extracts browser name from $userAgent.
    //  *
    //  * @param string $userAgent
    //  * @return string
    //  */
    // public static function extractBrowserInfo($userAgent)
    // {
    //     // Match major browsers (Chrome, Firefox, Safari, Edge, Opera, etc.)
    //     if (preg_match('/(Chrome|Firefox|Safari|Edge|Opera|OPR|MSIE|Trident)[\/ ]([\d.]+)/', $userAgent, $matches)) {
    //         $browser = $matches[1];
    //         $version = $matches[2];

    //         // Fix for Opera (uses "OPR" in User-Agent)
    //         if ($browser == 'OPR') {
    //             $browser = 'Opera';
    //         }

    //         // Fix for Internet Explorer (uses "Trident" in newer versions)
    //         if ($browser == 'Trident') {
    //             preg_match('/rv:([\d.]+)/', $userAgent, $rvMatches);
    //             $version = $rvMatches[1] ?? $version;
    //             $browser = 'Internet Explorer';
    //         }

    //         return "$browser $version";
    //     }

    //     return "Unknown Browser";
    // }
}
