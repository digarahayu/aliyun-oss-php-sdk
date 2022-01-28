<?php
namespace Oss;

use OSS\Core\OssException;
use OSS\Crypto\BaseCryptoProvider;
use OSS\Http\ResponseCore;
use OSS\Model\ContentCryptoMaterial;

/**
 * Class OssClient
 *
 * Object Storage Service(OSS)'s client class, which wraps all OSS APIs user could call to talk to OSS.
 * Users could do operations on bucket, object, including MultipartUpload or setting ACL via an OSSClient instance.
 * For more details, please check out the OSS API document:https://www.alibabacloud.com/help/doc-detail/31947.htm
 */
class OssEncryptionClient extends OssClient {

    const X_OSS_META_CLIENT_SIDE_ENCRYPTION_KEY = 'x-oss-meta-client-side-encryption-key';
    const X_OSS_META_CLIENT_SIDE_ENCRYPTION_START = 'x-oss-meta-client-side-encryption-start';
    const X_OSS_META_CLIENT_SIDE_ENCRYPTION_CEK_ALG = 'x-oss-meta-client-side-encryption-cek-alg';
    const X_OSS_META_CLIENT_SIDE_ENCRYPTION_WRAP_ALG = 'x-oss-meta-client-side-encryption-wrap-alg';
    const X_OSS_META_CLIENT_SIDE_ENCRYPTION_MATDESC='x-oss-meta-client-side-encryption-matdesc';
    const X_OSS_META_CLIENT_SIDE_ENCRYPTION_UNENCRYPTED_CONTENT_LENGTH='x-oss-meta-client-side-encryption-unencrypted-content-length';
    const X_OSS_META_CLIENT_SIDE_ENCRYPTION_UNENCRYPTED_CONTENT_MD5 = 'x-oss-meta-client-side-encryption-unencrypted-content-md5';
    const X_OSS_META_CLIENT_SIDE_ENCRYPTION_DATA_SIZE = 'x-oss-meta-client-side-encryption-data-size';
    const X_OSS_META_CLIENT_SIDE_ENCRYPTION_PART_SIZE = 'x-oss-meta-client-side-encryption-part-size';

    /**
     * @var BaseCryptoProvider
     */
    private $cryptoProvider;

    /**
     * OssEncryptionClient constructor.
     * There're a few different ways to create an OssEncryptionClient object:
     * 1. Most common one from access Id, access Key and the endpoint: $ossClient = new OssEncryptionClient($id, $key, $endpoint)
     * 2. If the endpoint is the CName (such as www.testoss.com, make sure it's CName binded in the OSS console),
     *    uses $ossClient = new OssClient($id, $key, $endpoint, true)
     * 3. If using Alicloud's security token service (STS), then the AccessKeyId, AccessKeySecret and STS token are all got from STS.
     * Use this: $ossClient = new OssClient($id, $key, $endpoint, false, $token)
     * 4. If the endpoint is in IP format, you could use this: $ossClient = new OssEncryptionClient($id, $key, “1.2.3.4:8900”)
     * @param string $accessKeyId
     * @param string $accessKeySecret
     * @param string $endpoint
     * @param BaseCryptoProvider $cryptoProvider
     * @param false $isCName
     * @param null $securityToken
     * @param null $requestProxy
     * @throws OssException
     */
    public function __construct($accessKeyId, $accessKeySecret, $endpoint,$cryptoProvider, $isCName = false, $securityToken = NULL, $requestProxy = NULL)
    {
        parent::__construct($accessKeyId, $accessKeySecret, $endpoint, $isCName = false, $securityToken = NULL, $requestProxy = NULL);
        if (!$cryptoProvider instanceof BaseCryptoProvider){
            throw new OssException('Crypto provider must be an instance of BaseCryptoProvider');
        }
        $this->cryptoProvider = $cryptoProvider;
    }

    /**
     * Uploads the $content object to OSS.
     *
     * @param string $bucket bucket name
     * @param string $object objcet name
     * @param string $content The content object
     * @param array $options
     * @return null
     */
    public function putObject($bucket, $object, $content, $options = NULL)
    {
        $this->cryptoProvider->cipher->resetContext();
        $contentCryptoMaterial =  $this->cryptoProvider->createContentMaterial();
        $encryptContent = $this->cryptoProvider->encryptAdapter($content,$contentCryptoMaterial->cipher);
        $headers = isset($options['headers']) ? $options['headers'] :array();
        $options['headers'] = $contentCryptoMaterial->addObjectMeta($headers);
        return parent::putObject($bucket, $object, $encryptContent, $options);
    }


    /**
     * @param string $bucket
     * @param string $object
     * @param null $options
     * @return false|\OSS\Http\ResponseCore|string
     */
    public function getObject($bucket, $object,$options = NULL)
    {
        $this->cryptoProvider->cipher->resetContext();
        if (isset($options[OssClient::OSS_FILE_DOWNLOAD])){
            unset($options[OssClient::OSS_FILE_DOWNLOAD]);
        }
        if(isset($options[OssClient::OSS_RANGE])){
            $this->cryptoProvider->cipher->calcOffset($options[OssClient::OSS_RANGE]);
        }
        $response = parent::getObject($bucket, $object, $options);
        return $this->getObjectResult($response);
    }


    /**
     * Initialize a multi-part upload
     *
     * @param string $bucket bucket name
     * @param string $object object name
     * @param array $options Key-Value array
     * @throws OssException
     * @return string returns uploadid
     */
    public function initiateMultipartUpload($bucket, $object, $options = NULL)
    {
        $this->cryptoProvider->cipher->resetContext();
        $contentCryptoMaterial =  $this->cryptoProvider->createContentMaterial();
        $headers = isset($options['headers']) ? $options['headers'] :array();
        $options['headers'] = $contentCryptoMaterial->addObjectMeta($headers);
        return parent::initiateMultipartUpload($bucket, $object, $options);
    }

    /**
     * Computes the parts count, size and start position according to the file size and the part size.
     * It must be only called by upload_Part().
     *
     * @param integer $file_size File size
     * @param integer $partSize part大小,part size. Default is 5MB
     * @return array An array contains key-value pairs--the key is `seekTo`and value is `length`.
     */
    public function generateMultiuploadParts($file_size, $partSize = 5242880)
    {
        return parent::generateMultiuploadParts($file_size, $partSize);
    }

    /**
     * Upload a part in a multiparts upload.
     *
     * @param string $bucket bucket name
     * @param string $object object name
     * @param string $uploadId
     * @param array $options Key-Value array
     * @return string eTag
     * @throws OssException
     */
    public function uploadPart($bucket, $object, $uploadId, $options = null)
    {
        $encryptContent = $this->cryptoProvider->encryptAdapter($options[OssClient::OSS_CONTENT],$this->cryptoProvider->cipher);
        return parent::uploadPartEncrypt($bucket, $object, $encryptContent,$uploadId, $options);
    }


    /**
     * @param $response
     * @return false|string
     * @throws OssException
     */
    private function getObjectResult(ResponseCore $response){
        $contentCryptoMaterial =  new ContentCryptoMaterial($this->cryptoProvider->cipher,$this->cryptoProvider->wrapAlg);
        $contentCryptoMaterial->fromObjectMeta($response->header);
        if(!$contentCryptoMaterial->isUnencrypted()){
            if ($contentCryptoMaterial->matDesc != $this->cryptoProvider->matDesc){
                $encryptionMaterials = $this->cryptoProvider->getEncryptionMaterials($contentCryptoMaterial->matDesc);
                if($encryptionMaterials){
                    $this->cryptoProvider = $this->cryptoProvider->resetEncryptionMaterials($encryptionMaterials);
                }else{
                    throw new OssException('There is no encryption materials match the material description of the object');
                }
            }
            $key = $this->cryptoProvider->decryptKey($contentCryptoMaterial->encryptedKey);
            $iv = $this->cryptoProvider->decryptIv($contentCryptoMaterial->encryptedIv);
            $this->cryptoProvider->cipher->init($key,$iv);
            return $this->cryptoProvider->decryptAdapter($response->body,$this->cryptoProvider->cipher);
        }
    }
}