<?php
namespace OSS\Crypto;
use OSS\Core\OssException;
use OSS\Crypto\Cipher\Aes\AesCipher;
use OSS\Model\ContentCryptoMaterial;
/**
 * Class BaseCryptoProvider
 * @package OSS\Crypto
 */
abstract class BaseCryptoProvider
{
    /**
     * mat desc
     * @var string
     */
    public $matDesc;

    /**
     * @var AesCipher
     */
    public $cipher;

    /**
     * @var string
     */
    public $cipherAdaptor;

    /**
     * @var array
     */
    public $encryptionMaterials = array();
    /**
     * BaseCryptoProvider constructor.
     * @param $cipher string
     * @param null $matDesc
     * @throws \Exception
     */
    public function __construct($cipherAdaptor="AesCtrCipher",$matDesc=null)
    {
        $this->cipherAdaptor = $cipherAdaptor;
        $class = "OSS\\Crypto\\Cipher\\".$cipherAdaptor;
        if (class_exists($class)) {
            $this->cipher = new $class();
        } else {
            throw new OssException('Error: Could not load Cipher adaptor ' . $cipherAdaptor . '!');
        }
        if($matDesc != null){
            if(is_array($matDesc)){
                $this->matDesc = $matDesc;
            }else{
                throw new OssException('Invalid type, the type of mat_desc must be array!');
            }
        }
    }

    /**
     * @param $encryptedKey string
     */
    public function decryptKey($encryptedKey){}

    /**
     * @param $encryptedIv
     */
    public function decryptIv($encryptedIv){}

    /**
     * Assemble encrypted information
     * @return KmsEncryptionMaterials or PsaEncryptionMaterials object
     */
    public function addEncryptionMaterials($encryptionMaterials){
        $key = key($encryptionMaterials->desc);
        $this->encryptionMaterials[$key] = $encryptionMaterials;
    }


    /**
     * @param $desc
     * @return KmsEncryptionMaterials or PsaEncryptionMaterials object
     */
    public function getEncryptionMaterials($desc){
        $key = key($desc);
        if(array_key_exists($key,$this->encryptionMaterials)){
            return $this->encryptionMaterials[$key];
        }
    }

    /**
     * Assemble encrypted information
     * @return ContentCryptoMaterial
     */
    public function createContentMaterial(){}

    /**
     * @param $encryptionMaterials  KmsEncryptionMaterials | RsaEncryptionMaterials
     */
    public function resetEncryptionMaterials($encryptionMaterials){

    }

}