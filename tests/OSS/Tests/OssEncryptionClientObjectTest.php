<?php

namespace OSS\Tests;

use OSS\Core\OssException;
use OSS\Core\OssUtil;
use OSS\Crypto\KmsEncryptionMaterials;
use Oss\Crypto\KmsProvider;
use OSS\Crypto\RsaEncryptionMaterials;
use OSS\Crypto\RsaProvider;
use OSS\OssClient;
use Oss\OssEncryptionClient;
require_once __DIR__ . '/../../samples/Config.php';
require_once __DIR__ . DIRECTORY_SEPARATOR . 'Common.php';
require_once __DIR__ . DIRECTORY_SEPARATOR . 'TestOssClientBase.php';

class OssEncryptionClientObjectTest extends TestOssClientBase
{

    private $ossEncryptionClient;

    public function testRsaObject(){
        $content = file_get_contents(__FILE__);
        $object = "encry.txt";
        $keys = array(
            'public_key' => 'rsa_public_key.pem',
            'private_key' => 'rsa_private_key.pem'
        );
        $matDesc= array(
            'key1'=>'test-one'
        );
        $provider= new RsaProvider($keys,$matDesc);
        $this->ossEncryptionClient = Common::getOssEncryptionClient($provider);
        try {
            $result = $this->ossEncryptionClient->putObject($this->bucket,$object,$content);
            $this->assertNotNull($result['oss-requestheaders']['x-oss-meta-client-side-encryption-cek-alg']);
        }catch (OssException $e){
           $this->assertTrue(false);
        }

        try {
            $result = $this->ossEncryptionClient->getObject($this->bucket,$object);
            $this->assertEquals($result,$content);
        }catch (OssException $e){
            $this->assertTrue(false);
        }


        $content2 = "Hi,hello This is a test";
        $object2 = "encry2.txt";

        try {
            $result = $this->ossEncryptionClient->putObject($this->bucket,$object2,$content2);
            $this->assertNotNull($result['oss-requestheaders']['x-oss-meta-client-side-encryption-cek-alg']);
        }catch (OssException $e){
            $this->assertTrue(false);
        }

        try {
            $result2 = $this->ossEncryptionClient->getObject($this->bucket,$object2);
            $this->assertEquals($result2,$content2);
        }catch (OssException $e){
            $this->assertTrue(false);
        }

        try {
            $result = $this->ossEncryptionClient->putObject($this->bucket,$object2,$content2);
            $this->assertNotNull($result['oss-requestheaders']['x-oss-meta-client-side-encryption-cek-alg']);
        }catch (OssException $e){
            $this->assertTrue(false);
        }

        try {
            $result2 = $this->ossEncryptionClient->getObject($this->bucket,$object2);
            $this->assertEquals($result2,$content2);
        }catch (OssException $e){
            $this->assertTrue(false);
        }


        try {
            Common::waitMetaSync();
            $keys = array(
                'public_key' => 'rsa2_public_key.pem',
                'private_key' => 'rsa2_private_key.pem'
            );
            $matDesc= array(
                'key2'=>'test-two'
            );
            $provider= new RsaProvider($keys,$matDesc);
            $this->ossEncryptionClient = Common::getOssEncryptionClient($provider);
            $result = $this->ossEncryptionClient->putObject($this->bucket,$object2,$content2);
            $this->assertNotNull($result['oss-requestheaders']['x-oss-meta-client-side-encryption-cek-alg']);
        }catch (OssException $e){
            $this->assertTrue(false);
        }

        try {
            Common::waitMetaSync();
            $keys2 = array(
                'public_key' => 'rsa2_public_key.pem',
                'private_key' => 'rsa2_private_key.pem'
            );
            $matDesc2= array(
                'key2'=>'test-two'
            );
            $encryptionMaterials = new RsaEncryptionMaterials($matDesc2,$keys2);
            $provider->addEncryptionMaterials($encryptionMaterials);
            $this->ossEncryptionClient = Common::getOssEncryptionClient($provider);
            $result = $this->ossEncryptionClient->getObject($this->bucket,$object2);
            $this->assertEquals($result,$content2);
        }catch (OssException $e){
            $this->assertTrue(false);
        }

    }

    public function testRsaMultiUploadAndDownload(){
        $object = "multi-upload.rar";
        try {
            $keys = array(
                'public_key' => 'rsa_public_key.pem',
                'private_key' => 'rsa_private_key.pem'
            );
            $matDesc= array(
                'key1'=>'test-one'
            );
            $provider= new RsaProvider($keys,$matDesc);
            $this->ossEncryptionClient = Common::getOssEncryptionClient($provider);
            $partSize = 5 * 1024 * 1024;
            $uploadFile = 'dnmp.rar';
            $uploadFileSize = sprintf('%u',filesize($uploadFile));
            $options['headers'] = array(
                OssEncryptionClient::X_OSS_META_CLIENT_SIDE_ENCRYPTION_DATA_SIZE => $uploadFileSize,
                OssEncryptionClient::X_OSS_META_CLIENT_SIDE_ENCRYPTION_PART_SIZE=>$partSize
            );
            $uploadId = $this->ossEncryptionClient->initiateMultipartUpload($this->bucket, $object,$options);
            $pieces = $this->ossEncryptionClient->generateMultiuploadParts($uploadFileSize, $partSize);
            $responseUploadPart = array();
            $uploadPosition = 0;
            foreach ($pieces as $i => $piece) {
                $fromPos = $uploadPosition + (integer)$piece[OssClient::OSS_SEEK_TO];
                $toPos = (integer)$piece[OssClient::OSS_LENGTH] + $fromPos - 1;
                $content = OssUtil::getDataFromFile($uploadFile,$fromPos,$toPos);
                $upOptions = array(
                    OssClient::OSS_PART_NUM => ($i + 1),
                    OssClient::OSS_CONTENT => $content,
                );
                $responseUploadPart[] = $this->ossEncryptionClient->uploadPart($this->bucket, $object, $uploadId, $upOptions);
                printf( "initiateMultipartUpload, uploadPart - part#{$i} OK\n");
            }
            $uploadParts = array();
            foreach ($responseUploadPart as $i => $eTag) {
                $uploadParts[] = array(
                    'PartNumber' => ($i + 1),
                    'ETag' => $eTag,
                );
            }
            $this->ossEncryptionClient->completeMultipartUpload($this->bucket, $object, $uploadId, $uploadParts);
            printf("completeMultipartUpload OK\n");
        }catch (OssException $e) {
            printf($e->getMessage() . "\n");
            $this->assertTrue(false);
        }


        try {
            $download = 'dnmp2.rar';
            $objectMeta = $this->ossEncryptionClient->getObjectMeta($this->bucket, $object);
            $size = $objectMeta['content-length'];
            $partSize =1024*1024*5;
            $pieces2 = $this->ossEncryptionClient->generateMultiuploadParts($size, $partSize);
            $downloadPosition = 0;
            if (file_exists($download)){
                unlink($download);
            }
            foreach ($pieces2 as $i => $piece2) {
                $fromPos2 = $downloadPosition + (integer)$piece2[OssClient::OSS_SEEK_TO];
                $toPos2 = (integer)$piece2[OssClient::OSS_LENGTH] + $fromPos2 - 1;
                $downOptions = array(
                    OssClient::OSS_RANGE => $fromPos2.'-'.$toPos2
                );
                $content2 = $this->ossEncryptionClient->getObject($this->bucket,$object,$downOptions);
                file_put_contents($download, $content2,FILE_APPEND );
                printf("Multi download, part - part#{$i} OK\n");
            }
            $this->assertEquals(md5_file($uploadFile),md5_file($download));
        }catch (OssException $e){
            printf($e->getMessage() . "\n");
            $this->assertTrue(false);
        }
    }


    public function testResumeUploadAndDownload(){
        $object = "multi-upload.rar";
        $keys = array(
            'public_key' => 'rsa_public_key.pem',
            'private_key' => 'rsa_private_key.pem'
        );
        $matDesc= array(
            'key1'=>'test-one'
        );
        $provider= new RsaProvider($keys,$matDesc);
        $this->ossEncryptionClient = Common::getOssEncryptionClient($provider);
        try{
            $partSize = 5 * 1024 * 1024;
            $uploadFile = 'dnmp.rar';
            $uploadFileSize = sprintf('%u',filesize($uploadFile));
            $options['headers'] = array(
                OssEncryptionClient::X_OSS_META_CLIENT_SIDE_ENCRYPTION_DATA_SIZE => $uploadFileSize,
                OssEncryptionClient::X_OSS_META_CLIENT_SIDE_ENCRYPTION_PART_SIZE=>$partSize
            );
            $uploadId = $this->ossEncryptionClient->initiateMultipartUpload($this->bucket, $object,$options);
            $pieces = $this->ossEncryptionClient->generateMultiuploadParts($uploadFileSize, $partSize);
            $responseUploadPart = array();
            $uploadPosition = 0;
            $uploadInfo = array(
                'uploadId' =>$uploadId,
                'object'=>$object,
                'uploadFile'=>$uploadFile,
                'partSize'=>$partSize,
            );
            foreach ($pieces as $i => $piece) {
                $fromPos = $uploadPosition + (integer)$piece[OssClient::OSS_SEEK_TO];
                $toPos = (integer)$piece[OssClient::OSS_LENGTH] + $fromPos - 1;
                $content = OssUtil::getDataFromFile($uploadFile,$fromPos,$toPos);
                $upOptions = array(
                    OssClient::OSS_PART_NUM => ($i + 1),
                    OssClient::OSS_CONTENT => $content,
                );
                $responseUploadPart[] = $this->ossEncryptionClient->uploadPart($this->bucket, $object, $uploadId, $upOptions);
                $uploadInfo['parts'] = $responseUploadPart;
                file_put_contents('upload.ucp',json_encode($uploadInfo));
                if ($i == 2){
                    break;
                }
            }
        }catch (OssException $e) {
            printf($e->getMessage() . "\n");
            $this->assertTrue(false);
        }
        try{
            $str = file_get_contents("upload.ucp");
            $uploadInfo = json_decode($str,true);
            $uploadId = $uploadInfo['uploadId'];
            $parts = $uploadInfo['parts'];
            $object = $uploadInfo['object'];
            $partSize = $uploadInfo['partSize'];
            $uploadFile = $uploadInfo['uploadFile'];
            $uploadFileSize = sprintf('%u',filesize($uploadFile));
            $num = count($parts);
            $uploadFile = 'dnmp.rar';
            $pieces = $this->ossEncryptionClient->generateMultiuploadParts($uploadFileSize, $partSize);
            $responseUploadPart = array();
            $uploadPosition = 0;
            foreach ($pieces as $i => $piece) {
                if($i < $num){
                    continue;
                }
                $fromPos = $uploadPosition + (integer)$piece[OssClient::OSS_SEEK_TO];
                $toPos = (integer)$piece[OssClient::OSS_LENGTH] + $fromPos - 1;
                $content = OssUtil::getDataFromFile($uploadFile,$fromPos,$toPos);
                $upOptions = array(
                    OssClient::OSS_PART_NUM => ($i + 1),
                    OssClient::OSS_CONTENT => $content,
                );
                $responseUploadPart[] = $this->ossEncryptionClient->uploadPart($this->bucket, $object, $uploadId, $upOptions);
            }
            $responseUploadPart = array_merge($parts,$responseUploadPart);
            foreach ($responseUploadPart as $i => $eTag) {
                $uploadParts[] = array(
                    'PartNumber' => ($i + 1),
                    'ETag' => $eTag,
                );
            }
            $this->ossEncryptionClient->completeMultipartUpload($this->bucket, $object, $uploadId, $uploadParts);
        }catch (OssException $e) {
            printf($e->getMessage() . "\n");
            $this->assertTrue(false);
        }

        try {
            $download = "demo.rar";
            $objectMeta = $this->ossEncryptionClient->getObjectMeta($this->bucket, $object);
            $size = $objectMeta['content-length'];
            $partSize =1024*1024*5;

            $pieces = $this->ossEncryptionClient->generateMultiuploadParts($size, $partSize);
            $downloadPosition = 0;
            $downloadArray = array(
                "object" => $object,
                "pieces" => $pieces,
            );
            foreach ($pieces as $i => $piece) {
                $fromPos = $downloadPosition + (integer)$piece[OssClient::OSS_SEEK_TO];
                $toPos = (integer)$piece[OssClient::OSS_LENGTH] + $fromPos - 1;
                $downOptions = array(
                    OssClient::OSS_RANGE => $fromPos.'-'.$toPos
                );
                $content = $this->ossEncryptionClient->getObject($this->bucket,$object,$downOptions);
                file_put_contents($download, $content,FILE_APPEND );
                $downloadArray['parts'] = $i+1;

                if ($i == 2){
                    break;
                }
            }

            file_put_contents("download.ucp",json_encode($downloadArray));
            printf( "Object ".$object.'download complete');
        }catch (OssException $e){
            printf($e->getMessage() . "\n");
            $this->assertTrue(false);
        }


        try {
            $str = file_get_contents('download.ucp');
            $downloadInfo = json_decode($str,true);
            $num = $downloadInfo['parts'];
            $pieces = $downloadInfo['pieces'];
            $object = $downloadInfo['object'];
            $downloadPosition = 0;
            foreach ($pieces as $i => $piece) {
                if($i < $num){
                    continue;
                }
                $fromPos = $downloadPosition + (integer)$piece[OssClient::OSS_SEEK_TO];
                $toPos = (integer)$piece[OssClient::OSS_LENGTH] + $fromPos - 1;
                $downOptions = array(
                    OssClient::OSS_RANGE => $fromPos.'-'.$toPos
                );
                $content = $this->ossEncryptionClient->getObject($this->bucket,$object,$downOptions);
                file_put_contents($download, $content,FILE_APPEND );
            }
            $this->assertEquals(md5_file($download),md5_file($uploadFile));
        }catch (OssException $e){
            printf($e->getMessage() . "\n");
            $this->assertTrue(false);
        }

        try {
            $download = "demo.rar";
            if (file_exists($download)){
                unlink($download);
            }
            $result = $this->ossEncryptionClient->getObject($this->bucket, $object);
            file_put_contents($download,$result);
            $this->assertEquals(md5_file($uploadFile),md5_file($download));
        }catch (OssException $e){
            printf($e->getMessage() . "\n");
            $this->assertTrue(false);
        }

    }

    public function testRsaRangeDownload(){
        $content = file_get_contents(__FILE__);
        $object = "encry.txt";
        $keys = array(
            'public_key' => 'rsa_public_key.pem',
            'private_key' => 'rsa_private_key.pem'
        );
        $matDesc= array(
            'key1'=>'test-one'
        );
        $provider= new RsaProvider($keys,$matDesc);
        $this->ossEncryptionClient = Common::getOssEncryptionClient($provider);
        try {
            $result = $this->ossEncryptionClient->putObject($this->bucket,$object,$content);
            $this->assertNotNull($result['oss-requestheaders']['x-oss-meta-client-side-encryption-cek-alg']);
        }catch (OssException $e){
            $this->assertTrue(false);
        }
        try {
            $options = array(
                OssClient::OSS_RANGE => '48-100'
            );
            $result = $this->ossEncryptionClient->getObject($this->bucket,$object,$options);
            $this->assertEquals($result,OssUtil::getDataFromFile(__FILE__,48,100));
        }catch (OssException $e){
            $this->assertTrue(false);
        }
    }

    public function testKmsObject(){
        $content = file_get_contents(__FILE__);
        $object = "kms-encry.txt";
        $matDesc= array(
            'key2'=>'test-kms'
        );
        $cmkId= '9cb1df43-d4dc-41d6-88c4-55a8f821b8f9';
        $provider= new KmsProvider(Common::getAccessKeyId(),Common::getAccessKeySecret(),Common::getKmsEndPoint(),$cmkId,$matDesc);
        $this->ossEncryptionClient = Common::getOssEncryptionClient($provider);
        try {
            $result = $this->ossEncryptionClient->putObject($this->bucket,$object,$content);
            $this->assertNotNull($result['oss-requestheaders']['x-oss-meta-client-side-encryption-cek-alg']);
        }catch (OssException $e){
            $this->assertTrue(false);
        }
        try {
            $result = $this->ossEncryptionClient->getObject($this->bucket,$object);
            $this->assertEquals($result,$content);
        }catch (OssException $e){
            $this->assertTrue(false);
        }


        $content2 = "Hi,hello This is a test";
        $object2 = "kms-encry2.txt";
        $matDesc= array(
            'key1'=>'test-kms-two'
        );
        $cmkId= '94e7c495-5d82-4085-9b02-92e4ce4e0a49';
        $provider= new KmsProvider(Common::getAccessKeyId(),Common::getAccessKeySecret(),Common::getKmsEndPointOther(),$cmkId,$matDesc);
        $otherKmsRegion = Common::getKmsEndPoint();
        $matDesc2= array(
            'key2'=>'test-kms'
        );
        $kmsId2 = "9cb1df43-d4dc-41d6-88c4-55a8f821b8f9";
        $encryptionMaterials = new KmsEncryptionMaterials($matDesc2,$otherKmsRegion,$kmsId2);
        $provider->addEncryptionMaterials($encryptionMaterials);
        $this->ossEncryptionClient = Common::getOssEncryptionClient($provider);

        try {
            $result = $this->ossEncryptionClient->putObject($this->bucket,$object2,$content2);
            $this->assertNotNull($result['oss-requestheaders']['x-oss-meta-client-side-encryption-cek-alg']);
        }catch (OssException $e){
            $this->assertTrue(false);
        }
        try {
            $result = $this->ossEncryptionClient->getObject($this->bucket,$object);
            $this->assertEquals($result,$content);
        }catch (OssException $e){
            $this->assertTrue(false);
        }

        try {
            $result = $this->ossEncryptionClient->putObject($this->bucket,$object2,$content2);
            $this->assertNotNull($result['oss-requestheaders']['x-oss-meta-client-side-encryption-cek-alg']);
        }catch (OssException $e){
            $this->assertTrue(false);
        }

        try {
            $result2 = $this->ossEncryptionClient->getObject($this->bucket,$object2);
            $this->assertEquals($result2,$content2);
        }catch (OssException $e){
            $this->assertTrue(false);
        }

    }


    public function testKmsMultiUploadAndDownload(){
        $object = "multi-upload.rar";
        try {
            $matDesc= array(
                'key1'=>'test-kms-two'
            );
            $cmkId= '94e7c495-5d82-4085-9b02-********';
            $provider= new KmsProvider(Common::getAccessKeyId(),Common::getAccessKeySecret(),Common::getKmsEndPointOther(),$cmkId,$matDesc);
            $otherKmsRegion = Common::getKmsEndPoint();
            $matDesc2= array(
                'key2'=>'test-kms'
            );
            $kmsId2 = "9cb1df43-d4dc-41d6-88c4-********";
            $encryptionMaterials = new KmsEncryptionMaterials($matDesc2,$otherKmsRegion,$kmsId2);
            $provider->addEncryptionMaterials($encryptionMaterials);
            $this->ossEncryptionClient = Common::getOssEncryptionClient($provider);
            $partSize = 5 * 1024 * 1024;
            $uploadFile = 'dnmp.rar';
            $uploadFileSize = sprintf('%u',filesize($uploadFile));
            $options['headers'] = array(
                OssEncryptionClient::X_OSS_META_CLIENT_SIDE_ENCRYPTION_DATA_SIZE => $uploadFileSize,
                OssEncryptionClient::X_OSS_META_CLIENT_SIDE_ENCRYPTION_PART_SIZE=>$partSize
            );
            $uploadId = $this->ossEncryptionClient->initiateMultipartUpload($this->bucket, $object,$options);
            $pieces = $this->ossEncryptionClient->generateMultiuploadParts($uploadFileSize, $partSize);
            $responseUploadPart = array();
            $uploadPosition = 0;
            foreach ($pieces as $i => $piece) {
                $fromPos = $uploadPosition + (integer)$piece[OssClient::OSS_SEEK_TO];
                $toPos = (integer)$piece[OssClient::OSS_LENGTH] + $fromPos - 1;
                $content = OssUtil::getDataFromFile($uploadFile,$fromPos,$toPos);
                $upOptions = array(
                    OssClient::OSS_PART_NUM => ($i + 1),
                    OssClient::OSS_CONTENT => $content,
                );
                $responseUploadPart[] = $this->ossEncryptionClient->uploadPart($this->bucket, $object, $uploadId, $upOptions);
                printf( "initiateMultipartUpload, uploadPart - part#{$i} OK\n");
            }
            $uploadParts = array();
            foreach ($responseUploadPart as $i => $eTag) {
                $uploadParts[] = array(
                    'PartNumber' => ($i + 1),
                    'ETag' => $eTag,
                );
            }
            $this->ossEncryptionClient->completeMultipartUpload($this->bucket, $object, $uploadId, $uploadParts);
            printf("completeMultipartUpload OK\n");
        }catch (OssException $e) {
            printf($e->getMessage() . "\n");
            $this->assertTrue(false);
        }


        try {
            $download = 'dnmp2.rar';
            $objectMeta = $this->ossEncryptionClient->getObjectMeta($this->bucket, $object);
            $size = $objectMeta['content-length'];
            $partSize =1024*1024*5;
            $pieces2 = $this->ossEncryptionClient->generateMultiuploadParts($size, $partSize);
            $downloadPosition = 0;
            if (file_exists($download)){
                unlink($download);
            }
            foreach ($pieces2 as $i => $piece2) {
                $fromPos2 = $downloadPosition + (integer)$piece2[OssClient::OSS_SEEK_TO];
                $toPos2 = (integer)$piece2[OssClient::OSS_LENGTH] + $fromPos2 - 1;
                $downOptions = array(
                    OssClient::OSS_RANGE => $fromPos2.'-'.$toPos2
                );
                $content2 = $this->ossEncryptionClient->getObject($this->bucket,$object,$downOptions);
                file_put_contents($download, $content2,FILE_APPEND );
                printf("Multi download, part - part#{$i} OK\n");
            }
            $this->assertEquals(md5_file($uploadFile),md5_file($download));
        }catch (OssException $e){
            printf($e->getMessage() . "\n");
            $this->assertTrue(false);
        }
    }


    public function testKmsResumeUploadAndDownload(){
        $object = "multi-upload.rar";
        $matDesc= array(
            'key1'=>'test-kms-two'
        );
        $cmkId= '********-5d82-4085-9b02-********';
        $provider= new KmsProvider(Common::getAccessKeyId(),Common::getAccessKeySecret(),Common::getKmsEndPointOther(),$cmkId,$matDesc);
        $otherKmsRegion = Common::getKmsEndPoint();
        $matDesc2= array(
            'key2'=>'test-kms'
        );
        $kmsId2 = "********-d4dc-41d6-88c4-********";
        $encryptionMaterials = new KmsEncryptionMaterials($matDesc2,$otherKmsRegion,$kmsId2);
        $provider->addEncryptionMaterials($encryptionMaterials);
        $this->ossEncryptionClient = Common::getOssEncryptionClient($provider);
        try{
            $partSize = 5 * 1024 * 1024;
            $uploadFile = 'dnmp.rar';
            $uploadFileSize = sprintf('%u',filesize($uploadFile));
            $options['headers'] = array(
                OssEncryptionClient::X_OSS_META_CLIENT_SIDE_ENCRYPTION_DATA_SIZE => $uploadFileSize,
                OssEncryptionClient::X_OSS_META_CLIENT_SIDE_ENCRYPTION_PART_SIZE=>$partSize
            );
            $uploadId = $this->ossEncryptionClient->initiateMultipartUpload($this->bucket, $object,$options);
            $pieces = $this->ossEncryptionClient->generateMultiuploadParts($uploadFileSize, $partSize);
            $responseUploadPart = array();
            $uploadPosition = 0;
            $uploadInfo = array(
                'uploadId' =>$uploadId,
                'object'=>$object,
                'uploadFile'=>$uploadFile,
                'partSize'=>$partSize,
            );
            foreach ($pieces as $i => $piece) {
                $fromPos = $uploadPosition + (integer)$piece[OssClient::OSS_SEEK_TO];
                $toPos = (integer)$piece[OssClient::OSS_LENGTH] + $fromPos - 1;
                $content = OssUtil::getDataFromFile($uploadFile,$fromPos,$toPos);
                $upOptions = array(
                    OssClient::OSS_PART_NUM => ($i + 1),
                    OssClient::OSS_CONTENT => $content,
                );
                $responseUploadPart[] = $this->ossEncryptionClient->uploadPart($this->bucket, $object, $uploadId, $upOptions);
                $uploadInfo['parts'] = $responseUploadPart;
                file_put_contents('upload.ucp',json_encode($uploadInfo));
                if ($i == 2){
                    break;
                }
            }
        }catch (OssException $e) {
            printf($e->getMessage() . "\n");
            $this->assertTrue(false);
        }

        try {
            $download = "demo.rar";
            if (file_exists($download)){
                unlink($download);
            }
            $result = $this->ossEncryptionClient->getObject($this->bucket, $object);
            file_put_contents($download,$result);
            $this->assertEquals(md5_file($uploadFile),md5_file($download));
        }catch (OssException $e){
            printf($e->getMessage() . "\n");
            $this->assertTrue(false);
        }

        try{
            $str = file_get_contents("upload.ucp");
            $uploadInfo = json_decode($str,true);
            $uploadId = $uploadInfo['uploadId'];
            $parts = $uploadInfo['parts'];
            $object = $uploadInfo['object'];
            $partSize = $uploadInfo['partSize'];
            $uploadFile = $uploadInfo['uploadFile'];
            $uploadFileSize = sprintf('%u',filesize($uploadFile));
            $num = count($parts);
            $uploadFile = 'dnmp.rar';
            $pieces = $this->ossEncryptionClient->generateMultiuploadParts($uploadFileSize, $partSize);
            $responseUploadPart = array();
            $uploadPosition = 0;
            foreach ($pieces as $i => $piece) {
                if($i < $num){
                    continue;
                }
                $fromPos = $uploadPosition + (integer)$piece[OssClient::OSS_SEEK_TO];
                $toPos = (integer)$piece[OssClient::OSS_LENGTH] + $fromPos - 1;
                $content = OssUtil::getDataFromFile($uploadFile,$fromPos,$toPos);
                $upOptions = array(
                    OssClient::OSS_PART_NUM => ($i + 1),
                    OssClient::OSS_CONTENT => $content,
                );
                $responseUploadPart[] = $this->ossEncryptionClient->uploadPart($this->bucket, $object, $uploadId, $upOptions);
            }
            $responseUploadPart = array_merge($parts,$responseUploadPart);
            foreach ($responseUploadPart as $i => $eTag) {
                $uploadParts[] = array(
                    'PartNumber' => ($i + 1),
                    'ETag' => $eTag,
                );
            }
            $this->ossEncryptionClient->completeMultipartUpload($this->bucket, $object, $uploadId, $uploadParts);
        }catch (OssException $e) {
            printf($e->getMessage() . "\n");
            $this->assertTrue(false);
        }

        try {
            $download = "demo.rar";
            $objectMeta = $this->ossEncryptionClient->getObjectMeta($this->bucket, $object);
            $size = $objectMeta['content-length'];
            $partSize =1024*1024*5;

            $pieces = $this->ossEncryptionClient->generateMultiuploadParts($size, $partSize);
            $downloadPosition = 0;
            $downloadArray = array(
                "object" => $object,
                "pieces" => $pieces,
            );
            foreach ($pieces as $i => $piece) {
                $fromPos = $downloadPosition + (integer)$piece[OssClient::OSS_SEEK_TO];
                $toPos = (integer)$piece[OssClient::OSS_LENGTH] + $fromPos - 1;
                $downOptions = array(
                    OssClient::OSS_RANGE => $fromPos.'-'.$toPos
                );
                $content = $this->ossEncryptionClient->getObject($this->bucket,$object,$downOptions);
                file_put_contents($download, $content,FILE_APPEND );
                $downloadArray['parts'] = $i+1;

                if ($i == 2){
                    break;
                }
            }

            file_put_contents("download.ucp",json_encode($downloadArray));
            printf( "Object ".$object.'download complete');
        }catch (OssException $e){
            printf($e->getMessage() . "\n");
            $this->assertTrue(false);
        }


        try {
            $str = file_get_contents('download.ucp');
            $downloadInfo = json_decode($str,true);
            $num = $downloadInfo['parts'];
            $pieces = $downloadInfo['pieces'];
            $object = $downloadInfo['object'];
            $downloadPosition = 0;
            foreach ($pieces as $i => $piece) {
                if($i < $num){
                    continue;
                }
                $fromPos = $downloadPosition + (integer)$piece[OssClient::OSS_SEEK_TO];
                $toPos = (integer)$piece[OssClient::OSS_LENGTH] + $fromPos - 1;
                $downOptions = array(
                    OssClient::OSS_RANGE => $fromPos.'-'.$toPos
                );
                $content = $this->ossEncryptionClient->getObject($this->bucket,$object,$downOptions);
                file_put_contents($download, $content,FILE_APPEND );
            }
            $this->assertEquals(md5_file($download),md5_file($uploadFile));
        }catch (OssException $e){
            printf($e->getMessage() . "\n");
            $this->assertTrue(false);
        }
    }
}


