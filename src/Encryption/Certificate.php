<?php

namespace Vegetation\Fern\Encryption;

class Certificate
{
    private $_config = [
        'public_key' => '',
        'private_key' => '',
    ];

    public function __construct($private_key_filepath, $public_key_filepath) {
        $this->_config['private_key'] = $this->_getContents($private_key_filepath);
        $this->_config['public_key'] = $this->_getContents($public_key_filepath);
    }

    /**
     * @uses 获取文件内容
     * @param $file_path string
     * @return bool|string
     */
    private function _getContents($file_path) {
        file_exists($file_path) or die ('密钥或公钥的文件路径错误');
        return file_get_contents($file_path);
    }

    /**
     * @uses 获取私钥
     * @return bool|resource
     */
    private function _getPrivateKey() {
        $priv_key = $this->_config['private_key'];
        return openssl_pkey_get_private($priv_key);
    }

    /**
     * @uses 获取公钥
     * @return bool|resource
     */
    private function _getPublicKey() {
        $public_key = $this->_config['public_key'];
        return openssl_pkey_get_public($public_key);
    }

    /**
     * @uses 私钥加密
     * @param string $data
     * @return null|string
     */
    public function privEncrypt($data = '') {
        if (!is_string($data)) {
            return null;
        }
        return openssl_private_encrypt($data, $encrypted, $this->_getPrivateKey()) ? base64_encode($encrypted) : null;
    }

    /**
     * @uses 公钥加密
     * @param string $data
     * @return null|string
     */
    public function publicEncrypt($data = '') {
        if (!is_string($data)) {
            return null;
        }
        return openssl_public_encrypt($data, $encrypted, $this->_getPublicKey()) ? base64_encode($encrypted) : null;
    }

    /**
     * @uses 私钥解密
     * @param string $encrypted
     * @return null
     */
    public function privDecrypt($encrypted = '') {
        if (!is_string($encrypted)) {
            return null;
        }
        return (openssl_private_decrypt(base64_decode($encrypted), $decrypted, $this->_getPrivateKey())) ? $decrypted : null;
    }

    /**
     * @uses 公钥解密
     * @param string $encrypted
     * @return null
     */
    public function publicDecrypt($encrypted = '') {
        if (!is_string($encrypted)) {
            return null;
        }
        return (openssl_public_decrypt(base64_decode($encrypted), $decrypted, $this->_getPublicKey())) ? $decrypted : null;
    }

    /**
     * @param $data
     * @param $padding
     * @return false|string
     * 分段加密
     */
    function publicEncryptBig($data,$padding = OPENSSL_PKCS1_PADDING) {
        $publicKey = $this->_config['public_key'];
        // 获取公钥的详细信息
        $publicKeyDetails = openssl_pkey_get_details(openssl_pkey_get_public($publicKey));
        $keyBits = $publicKeyDetails['bits'];
        $maxBytes = intval($keyBits / 8) - 11; // 减去填充和哈希字节（假设使用SHA-1）

        // 如果使用SHA-256或其他哈希算法，可能需要减去更多字节
        // $maxBytes = intval($keyBits / 8) - 41; // 假设使用SHA-256

        $encrypted = '';

        // 分割数据为较小的块
        for ($offset = 0; $offset < strlen($data); $offset += $maxBytes) {
            $chunk = substr($data, $offset, $maxBytes);

            // 如果最后一个块小于$maxBytes，则只加密该块
            if (strlen($chunk) < $maxBytes && $offset + $maxBytes > strlen($data)) {
                $chunk = substr($data, $offset);
            }

            $encryptedChunk = '';
            if (openssl_public_encrypt($chunk, $encryptedChunk, $publicKey, $padding)) {
                $encrypted .= $encryptedChunk;
            } else {
                // 处理错误
                return false;
            }
        }

        return base64_encode($encrypted); // 返回base64编码的加密数据
    }

    /**
     * @param $encryptedData
     * @param $padding
     * @return false|string
     * 大数据模式
     */
    public function privDecryptBig($encryptedData,$padding = OPENSSL_PKCS1_PADDING)
    {
        $decrypted = '';
        $privateKey = $this->_getPrivateKey();
        // 先进行base64解码
        $decodedData = base64_decode($encryptedData);

        // 获取私钥的详细信息（虽然这里不需要，但为了完整性）
        $privateKeyDetails = openssl_pkey_get_details(openssl_pkey_get_private($privateKey));
        $keyBits = $privateKeyDetails['bits'];
        $maxBytes = intval($keyBits / 8); // 解密时通常不需要减去填充和哈希字节，但需要处理填充

        // 假设加密数据时使用的是固定的块大小进行加密
        for ($offset = 0; $offset < strlen($decodedData); $offset += $maxBytes) {
            $chunk = substr($decodedData, $offset, $maxBytes);

            $decryptedChunk = '';
            if (openssl_private_decrypt($chunk, $decryptedChunk, $privateKey, $padding)) {
                $decrypted .= $decryptedChunk;
            } else {
                // 处理错误
                return false;
            }

            // 去除可能的填充字符（PKCS#1 v1.5填充）
            // 注意：这里只是简单地去掉最后一个可能的填充字符，实际情况可能需要更复杂的处理
            $decrypted = rtrim($decrypted, "\0");
        }

        // 如果使用PKCS#1 v1.5填充，并且数据被正确填充，上面的rtrim调用可能已经足够了
        // 但如果是OAEP填充或其他填充方式，则需要更复杂的处理

        return $decrypted;
    }
}