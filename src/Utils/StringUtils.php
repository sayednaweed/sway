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
}
