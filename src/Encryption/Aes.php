<?php

namespace Vegetation\Fern\Encryption;

class Aes
{
    /**
     * @var string
     * key
     */
    private $key = 'fai$%@dKDIDKDIE2DIDIDDKDIDKDIEDE';

    /**
     * @var string
     * iv
     */
    private $iv = '';

    /**
     * @param $key
     * @param $iv
     * 构造方法
     */
    public function __construct($key,$iv){
        $this->key = $key;
        $this->iv = $iv;
    }

    /**
     * AES-256-CBC 加密
     * @param $data
     * @return mixed|string
     */
    function encryptCbc($data)
    {
        $iv = $this->iv;
        $key = $this->key;
        $text = openssl_encrypt($data, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
        return base64_encode($text);
    }

    /**
     * AES-256-CBC 解密
     * @param $text
     * @return string
     */
    function decryptCbc($text)
    {
        $iv = $this->iv;
        $key = $this->key;
        $decodeText = base64_decode($text);
        $data = openssl_decrypt($decodeText, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
        return $data;
    }

    /**
     * AES-256-ECB 加密
     * @param $data
     * @return mixed|string
     */
    function encryptEcb($data)
    {
        $key = $this->key;
        $text = openssl_encrypt($data, 'AES-256-ECB', $key, 1);
        return base64_encode($text);
    }

    /**
     * AES-256-ECB 解密
     * @param $text
     * @return string
     */
    function decryptEcb($text)
    {
        $key = $this->key;
        $decodeText = base64_decode($text);
        $data = openssl_decrypt($decodeText, 'AES-256-ECB', $key, 1);
        return $data;
    }
}