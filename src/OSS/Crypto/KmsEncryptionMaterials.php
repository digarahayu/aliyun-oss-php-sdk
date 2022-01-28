<?php

namespace OSS\Crypto;

use OSS\Core\OssException;

/**
 * Class KmsEncryptionMaterials
 * @package OSS\Crypto
 */
class KmsEncryptionMaterials {

    public $desc = array();
    public $kmsRegion;
    public $kmsId;

    /**
     * KmsEncryptionMaterials constructor.
     * @param $desc array
     * @param $kmsRegion string 'kms.cn-hangzhou.aliyuncs.com'
     * @param $kmsId string
     * @throws OssException
     */
    public function __construct($desc, $kmsRegion,$kmsId)
    {
        if(!is_array($desc)){
            throw new OssException('Invalid type, the type of desc must be array!');
        }
        if(empty($kmsRegion)){
            throw new OssException('Kms Region is not null!');
        }

        if(empty($kmsId)){
            throw new OssException('Kms Id is not null!');
        }

        $this->kmsRegion = $kmsRegion;
        $this->desc = $desc;
        $this->kmsId = $kmsId;
    }
}
