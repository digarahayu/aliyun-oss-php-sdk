<?php
namespace OSS\Credentials;

class EnvironmentVariableCredentialsProvider implements CredentialsProvider
{

    /**
     * @return StaticCredentialsProvider
     */
    public function getCredentials()
    {
        $ak= getenv('OSS_ACCESS_KEY_ID');
        $sk = getenv('OSS_ACCESS_KEY_SECRET');
        $token =  getenv('OSS_SESSION_TOKEN');
        return new StaticCredentialsProvider($ak, $sk, $token);
    }
}
