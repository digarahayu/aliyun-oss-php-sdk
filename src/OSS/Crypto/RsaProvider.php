<?php

namespace OSS\Crypto;
use OSS\Core\OssException;
use OSS\Crypto\Cipher\Aes\AesCipher;
use OSS\Crypto\Cipher\AesCtrCipher;
use OSS\Model\ContentCryptoMaterial;

/**
 * Uses KMS to supply materials for encrypting and decrypting data
 * Class KmsMaterialsProvider
 * @package Oss\Crypto
 */
class RsaProvider extends BaseCryptoProvider
{
    public $wrapAlg;
    private $publicKey;
    private $privateKey;

    /**
     * RsaProvider constructor.
     * @param $keyPair
     * @param $cipher string AesCtrCipher
     * @param null $matDesc
     * @throws OssException
     */
    public function __construct($keyPair,$matDesc=null,$cipherAdaptor="AesCtrCipher")
    {
        parent::__construct($cipherAdaptor,$matDesc);
        $this->wrapAlg = Crypto::RSA_NONE_PKCS1Padding_WRAP_ALGORITHM;
        if(array_key_exists('public_key',$keyPair)){
            $this->publicKey = openssl_pkey_get_public(file_get_contents($keyPair['public_key']));
        }else{
            throw new OssException('Public key is Required!');
        }
        if(array_key_exists('private_key',$keyPair)){
            $this->privateKey = openssl_pkey_get_private(file_get_contents($keyPair['private_key']));
        }else{
            throw new OssException('Private key is Required!');
        }
    }

    /**
     * Assemble encrypted information
     * @return KmsEncryptionMaterials | RsaEncryptionMaterials
     */
    public function addEncryptionMaterials($encryptionMaterials){
        parent::addEncryptionMaterials($encryptionMaterials);
    }

    /**
     * Assemble encrypted information
     * @return KmsEncryptionMaterials | RsaEncryptionMaterials
     */
    public function getEncryptionMaterials($desc){
        return parent::getEncryptionMaterials($desc);
    }

    /**
     * get a random key
     * @return false|string|void
     */
    public function getKey()
    {
        return $this->cipher->getKey();
    }

    /**
     * get a random iv
     * @return string|void
     */
    public function getIv()
    {
        return $this->cipher->getIv();
    }

    /**
     * @param string $encryptedKey
     * @return string
     */
    public function decryptKey($encryptedKey)
    {
        return $this->decryptData($encryptedKey);
    }

    /**
     * @param $encryptedIv
     * @return string
     */
    public function decryptIv($encryptedIv)
    {
        return $this->decryptData($encryptedIv);
    }


    /**
     * @param $encryptionMaterials KmsEncryptionMaterials | RsaEncryptionMaterials
     * @return RsaProvider
     * @throws \Exception
     */
    public function resetEncryptionMaterials($encryptionMaterials)
    {
        return new RsaProvider($encryptionMaterials->keyPair,$encryptionMaterials->desc,$this->cipherAdaptor);
    }

    /**
     * @param $content
     * @param AesCtrCipher $cipher
     * @return false|string
     */
    public function encryptAdapter($content,$cipher){
        return $cipher->encrypt($content,$cipher);
    }


    /**
     * @param $content
     * @param AesCtrCipher $cipher
     * @return false|string
     */
    public function encryptContent($content,$cipher,$iv){
        return base64_encode(openssl_encrypt($content,$cipher->cipher,$cipher->key,OPENSSL_NO_PADDING,$iv));
    }


    /**
     * @param $content
     * @param AesCipher $cipher
     * @return false|string
     */
    public function decryptAdapter($content, $cipher)
    {
        return $cipher->decrypt($content,$cipher);
    }


    /**
     * Assemble encrypted information
     * @return ContentCryptoMaterial
     */
    public function createContentMaterial(){
        $key = $this->getKey();
        $encryptedKey = $this->encryptData($key);
        $iv = $this->getIv();
        $encrytedIv = $this->encryptData($iv);
        $cipher = $this->cipher;
        $wrapAlg = $this->wrapAlg;
        $matDesc = $this->matDesc;
        $this->cipher->init($key,$iv);
        $contentCryptoMaterial = new ContentCryptoMaterial($cipher,$wrapAlg,$encryptedKey,$encrytedIv,$matDesc);
        return $contentCryptoMaterial;
    }

    /**
     * encrypt a string
     * @param $data
     * @return string|null
     */
    public function encryptData($data){
        return openssl_public_encrypt($data, $encrypted, $this->publicKey) ? base64_encode($encrypted) : null;
    }

    /**
     * decrypt a string
     * @param $data
     * @return mixed|null
     */
    public function decryptData($data)
    {
        return openssl_private_decrypt($data, $decrypted, $this->privateKey) ? $decrypted : null;
    }
}