<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelVaultClient\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class KeyResource extends JsonResource
{
    public static $wrap = null;

    /**
     * Transform the resource into an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        return [
            'kid' => $this->id,
            'client_id' => $this->client_id,
            'version' => $this->version,
            'public_key' => $this->public_key,
            'valid_from' => $this->valid_from,
            'valid_until' => $this->valid_until,
            'private_key' => $this->when($this->private_key, $this->private_key),
        ];
    }
}
