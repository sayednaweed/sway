<?php

namespace Sway\Types;

class Payload
{
    private $tokenable_id;
    private $type;
    private $expires_at;

    /**
     * Constructor to initialize the payload fields.
     *
     * @param mixed $tokenable_id
     * @param string $expires_at
     * @param string $secret_key
     */
    public function __construct($tokenable_id, $type, string $expires_at)
    {
        $this->tokenable_id = $tokenable_id;
        $this->expires_at = $expires_at;
        $this->type = $type;
    }
    /**
     * Get the tokenable ID.
     *
     * @return mixed
     */
    public function getTokenableId()
    {
        return $this->tokenable_id;
    }
    /**
     * Get the expiration time.
     *
     * @return string
     */
    public function getType()
    {
        return $this->type;
    }

    /**
     * Get the expiration time.
     *
     * @return string
     */
    public function getExpiresAt()
    {
        return $this->expires_at;
    }
}
