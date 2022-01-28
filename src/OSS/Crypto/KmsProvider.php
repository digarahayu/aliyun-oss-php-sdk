<?php
namespace Oss\Crypto;

use Oss\KmsClient;
use OSS\Core\OssException;
use OSS\Model\ContentCryptoMaterial;
use OSS\Crypto\Cipher\Aes\AesCtrCipher;

/**
 * Uses KMS to supply materials for encrypting and decrypting data
 * Class KmsMaterialsProvider
 * @package Oss\Crypto
 */
class KmsProvider extends BaseCryptoProvider
{

    private $kmsClient;
    private $customerKeyId;
    public $wrapAlg;

    private $accessKeyId;
    private $accessKeySecret;

    /**
     * KmsProvider constructor.
     * @param $accessKeyId
     * @param $accessKeySecret
     * @param $region
     * @param $cmkId
     * @param $cipher AesCtrCipher
     */
    public function __construct($accessKeyId, $accessKeySecret, $region,$cmkId,$mat_desc=null,$cipherAdaptor="AesCtrCipher") {
        parent::__construct($cipherAdaptor,$mat_desc);
        $this->accessKeyId = $accessKeyId;
        $this->accessKeySecret = $accessKeySecret;
        $this->kmsClient = new KmsClient($accessKeyId,$accessKeySecret,$region);
        $this->customerKeyId = $cmkId;
        $this->wrapAlg = Crypto::KMS_ALI_WRAP_ALGORITHM;
    }

    /**
     * get a random key
     * @return array
     */
    public function getKey()
    {
        list($key,$encryptedKey) = $this->generateDataKey();
        return array($key,$encryptedKey);
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
     * @return ContentCryptoMaterial
     */
    public function createContentMaterial(){
        list($key,$encryptedKey)= $this->getKey();
        $iv = $this->getIv();
        $encrytedIv = $this->encryptData($iv);
        $cipher = $this->cipher;
        $wrapAlg = $this->wrapAlg;
        $matDesc = $this->matDesc;
        $this->cipher->init(base64_decode($key),$iv);
        return new ContentCryptoMaterial($cipher,$wrapAlg,$encryptedKey,$encrytedIv,$matDesc);
    }


    /**
     * @param $data
     * @return mixed
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function encryptData($data){
        $result = $this->kmsClient->encrypt([
            'KeyId' => $this->customerKeyId,
            "Plaintext" => $data
        ]);
        return $result['CiphertextBlob'];
    }

    /**
     * @param KmsEncryptionMaterials $encryptionMaterials
     * @return KmsProvider
     */
    public function resetEncryptionMaterials($encryptionMaterials)
    {
        $provider = $this;
        $this->kmsClient = new KmsClient($this->accessKeyId,$this->accessKeySecret,$encryptionMaterials->kmsRegion);
        $provider->matDesc = $encryptionMaterials->desc;
        $this->customerKeyId = $encryptionMaterials->kmsId;
        return $provider;
    }

    /**
     * Assemble encrypted information
     * @return KmsEncryptionMaterials
     */
    public function addEncryptionMaterials($encryptionMaterials){
        parent::addEncryptionMaterials($encryptionMaterials);
    }

    /**
     * Assemble encrypted information
     * @return KmsEncryptionMaterials
     */
    public function getEncryptionMaterials($desc){
        return parent::getEncryptionMaterials($desc);
    }


    /**
     * @param $content
     * @param AesCtrCipher $cipher
     * @return false|string
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function encryptAdapter($content, $cipher)
    {
        return $cipher->encrypt($content,$cipher);
    }

    /**
     * @param $content
     * @param $cipher AesCtrCipher
     * @return false|string
     */
    public function decryptAdapter($content, $cipher)
    {
        return $cipher->decrypt($content,$cipher);
    }


    /**
     * @param string $encryptedKey
     * @return string
     */
    public function decryptKey($encryptedKey)
    {
        return base64_decode($this->decryptData($encryptedKey));
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
     * @return array
     */
    public function generateDataKey()
    {
        $result = $this->kmsClient->generateDataKey([
            'KeyId' => $this->customerKeyId,
            'KeySpec' => "AES_256",
            "NumberOfBytes" => "32",
        ]);

        return array(
            $result['Plaintext'],
            $result['CiphertextBlob'],
        );
    }


    /**
     * @return array
     */
    public function decryptData($data)
    {
        $result = $this->kmsClient->decrypt([
            'CiphertextBlob' =>$data,
        ]);

        return $result['Plaintext'];

    }
}
