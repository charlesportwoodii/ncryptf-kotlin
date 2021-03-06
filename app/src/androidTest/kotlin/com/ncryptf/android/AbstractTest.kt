package com.ncryptf.android.Test

import org.threeten.bp.Instant;
import org.threeten.bp.ZoneOffset;
import org.threeten.bp.ZonedDateTime;

import android.util.Base64
import org.junit.Assert.*
import org.junit.Test

import com.ncryptf.android.Token
import com.ncryptf.android.Test.TestCase

abstract class AbstractTest
{
    protected var date: ZonedDateTime

    protected var salt: ByteArray

    protected var token: Token

    protected val testCases: Array<TestCase> = arrayOf(
        TestCase("GET", "/api/v1/test", ""),
        TestCase("GET", "/api/v1/test?foo=bar", ""),
        TestCase("GET", "/api/v1/test?foo=bar&a[a]=1", ""),
        TestCase("POST", "/api/v1/test", "{\"foo\":\"bar\"}"),
        TestCase("POST", "/api/v1/test", "{\"foo\":1}"),
        TestCase("POST", "/api/v1/test", "{\"foo\":false}"),
        TestCase("POST", "/api/v1/test", "{\"foo\":1.023}"),
        TestCase("DELETE", "/api/v1/test", "{\"alpha\": [\"a\", \"b\", \"c\"],\"obj\": {\"ints\": [1, 2, 3],\"floats\": [0.0, 1.1, 1.2, 1.3],\"bools\": [true, false],\"nil\": null,\"int\": 13,\"float\": 3.1415,\"bool\": true,\"nesting\": {\"nested\": true}}}"),
        TestCase("DELETE", "/api/v1/test?foo=bar", "{\"alpha\": [\"a\", \"b\", \"c\"],\"obj\": {\"ints\": [1, 2, 3],\"floats\": [0.0, 1.1, 1.2, 1.3],\"bools\": [true, false],\"nil\": null,\"int\": 13,\"float\": 3.1415,\"bool\": true,\"nesting\": {\"nested\": true}}}")
    )

    protected val v1SignatureResults: Array<String> = arrayOf(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "7a38bf81f383f69433ad6e900d35b3e2385593f76a7b7ab5d4355b8ba41ee24b",
        "37a76343c8e3c695feeaadfe52329673ff129c65f99f55ae6056c9254f4c481d",
        "4da787ba25545ca80765298be5676370dae5db4892e9ff59511a2c13ea20c7f5",
        "9782504e91ad436a9cf456454922cfe143163a2c1361882b0dffb754638b5050",
        "69b3df79d454e1fdd375e53612c61e5e0e5deaa9e98e5746296a52c6f2bad9bb",
        "69b3df79d454e1fdd375e53612c61e5e0e5deaa9e98e5746296a52c6f2bad9bb"
    )

    protected val v2SignatureResults: Array<String> = arrayOf(
        "N1pQ53yIzsaOXB4d8eGW9NjZx7rq5LpvWMdXHjZc3szfD96u5diwFaExSa4Ze6yfC/T099OETLaffCWjMoHQzw==",
        "N1pQ53yIzsaOXB4d8eGW9NjZx7rq5LpvWMdXHjZc3szfD96u5diwFaExSa4Ze6yfC/T099OETLaffCWjMoHQzw==",
        "N1pQ53yIzsaOXB4d8eGW9NjZx7rq5LpvWMdXHjZc3szfD96u5diwFaExSa4Ze6yfC/T099OETLaffCWjMoHQzw==",
        "cH3ZMCv5+dQqFKxuSSRmVaRvAiu3QQJ75gQAE1Q+M3ZI8GcNKdHOtl86JesbP31v/m7uHsAkbDgz0BsfBHKPIA==",
        "ZZW9zm1I0rZLr7++giav+lQ59b7AoVltfqK03MJsvAKr7qPHeda0qz/nGU3pqtZgJ3VozweIrORZWIspweJc1g==",
        "Mapt8KeGXDIFFPgs7YplHmykBfm9PkD4QHq0J+ozsdtpFcX5mB8xtj0SfVsxWeWLt7Ydm3CjOqHfOh3v/wMC4A==",
        "EWE0+YqAyzIr0vbSVXHSpcn/mnWr0I2oAmJ9Med2jVW9p5NbzxbDc4AhEbTT4ha9f7RQFJI0ddY1SzK8fK8LpQ==",
        "NTNNxhPRBFJd6g5QShHG44SwuHzWN4bVsKGe1vSXOr/ugRadeA4xiLMmnWSIsql/kILH1ez/asd3Y7Yv1BOqYQ==",
        "NTNNxhPRBFJd6g5QShHG44SwuHzWN4bVsKGe1vSXOr/ugRadeA4xiLMmnWSIsql/kILH1ez/asd3Y7Yv1BOqYQ=="
    )

    protected val v1HMACHeaders: Array<String> = arrayOf(
        "HMAC x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J,26TEEe+mUjhYmgXRcy4nL+awe6ksdahhjzujFo1B4UM=,efEY/IJdAbi474TtQCCjj2y1FGB4BFFPpbHm/1QtpyI=",
        "HMAC x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J,sdDSnLvddq6IBTv0H/o4hY4u9GFzLrgP5fL0NqFxz5A=,efEY/IJdAbi474TtQCCjj2y1FGB4BFFPpbHm/1QtpyI=",
        "HMAC x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J,1g+EfJQ2JnxxVeUfUINhweftK2gCqYpMtPuJ+rc6P4A=,efEY/IJdAbi474TtQCCjj2y1FGB4BFFPpbHm/1QtpyI=",
        "HMAC x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J,Tb4/56uZ7FDtBHAbwCgYFirrXW0uhkSRFjLOZYrpHdE=,efEY/IJdAbi474TtQCCjj2y1FGB4BFFPpbHm/1QtpyI=",
        "HMAC x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J,bxbitvadJE2APYi3rid3e5SM99X2urjl1vefvZeFGeI=,efEY/IJdAbi474TtQCCjj2y1FGB4BFFPpbHm/1QtpyI=",
        "HMAC x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J,O9BUjVPYZ4zE7rlaE2C5Qt0pAa8orAJhLbxIIxV66TU=,efEY/IJdAbi474TtQCCjj2y1FGB4BFFPpbHm/1QtpyI=",
        "HMAC x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J,38TB5rfmBJ+NhxQn1lWCeG4aseFuXUthwNz61WlsjIQ=,efEY/IJdAbi474TtQCCjj2y1FGB4BFFPpbHm/1QtpyI=",
        "HMAC x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J,2wECEgRUOq1B6v8p9t1qHQME53HQfAMpjS38qI6S01M=,efEY/IJdAbi474TtQCCjj2y1FGB4BFFPpbHm/1QtpyI=",
        "HMAC x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J,ddzN/izj4XNxKx/CkZAw9uB0SXDNmxPo1zC0wgQIcrM=,efEY/IJdAbi474TtQCCjj2y1FGB4BFFPpbHm/1QtpyI="
    )

    protected val v2HMACHeaders: Array<String> = arrayOf(
        "HMAC eyJhY2Nlc3NfdG9rZW4iOiJ4MmdNZUo1TnAwQ2NLcFphditpOWlpWGVRQnRhWU1RXC95ZUV0Y09nWTNKIiwiZGF0ZSI6IkZyaSwgMDMgQXVnIDIwMTggMTU6Mjc6NDggKzAwMDAiLCJobWFjIjoiaTZHQzFtZUtWQ3VhQTYzXC9FcXBUazVYZ2VEY3pvY0ErMWxUdE5STWhLcDQ9Iiwic2FsdCI6ImVmRVlcL0lKZEFiaTQ3NFR0UUNDamoyeTFGR0I0QkZGUHBiSG1cLzFRdHB5ST0iLCJ2IjoyfQ==",
        "HMAC eyJhY2Nlc3NfdG9rZW4iOiJ4MmdNZUo1TnAwQ2NLcFphditpOWlpWGVRQnRhWU1RXC95ZUV0Y09nWTNKIiwiZGF0ZSI6IkZyaSwgMDMgQXVnIDIwMTggMTU6Mjc6NDggKzAwMDAiLCJobWFjIjoiVFErejZKbzYyeDBLV0lKcjhZSzE1c1J5ZjExc09cL3daVFFhMGRBa0toT1k9Iiwic2FsdCI6ImVmRVlcL0lKZEFiaTQ3NFR0UUNDamoyeTFGR0I0QkZGUHBiSG1cLzFRdHB5ST0iLCJ2IjoyfQ==",
        "HMAC eyJhY2Nlc3NfdG9rZW4iOiJ4MmdNZUo1TnAwQ2NLcFphditpOWlpWGVRQnRhWU1RXC95ZUV0Y09nWTNKIiwiZGF0ZSI6IkZyaSwgMDMgQXVnIDIwMTggMTU6Mjc6NDggKzAwMDAiLCJobWFjIjoiXC9cL21uOExkTnhIU2hlVXkwVVVLd0VGRUxwVituVVNid2l6Y3BZUkNOM29ZPSIsInNhbHQiOiJlZkVZXC9JSmRBYmk0NzRUdFFDQ2pqMnkxRkdCNEJGRlBwYkhtXC8xUXRweUk9IiwidiI6Mn0=",
        "HMAC eyJhY2Nlc3NfdG9rZW4iOiJ4MmdNZUo1TnAwQ2NLcFphditpOWlpWGVRQnRhWU1RXC95ZUV0Y09nWTNKIiwiZGF0ZSI6IkZyaSwgMDMgQXVnIDIwMTggMTU6Mjc6NDggKzAwMDAiLCJobWFjIjoiY3I1TCsxR0hGeEdIVXV2VFJjVHdCNmJzKzk5ZmNEUDhWZTk2R29NTERtaz0iLCJzYWx0IjoiZWZFWVwvSUpkQWJpNDc0VHRRQ0NqajJ5MUZHQjRCRkZQcGJIbVwvMVF0cHlJPSIsInYiOjJ9",
        "HMAC eyJhY2Nlc3NfdG9rZW4iOiJ4MmdNZUo1TnAwQ2NLcFphditpOWlpWGVRQnRhWU1RXC95ZUV0Y09nWTNKIiwiZGF0ZSI6IkZyaSwgMDMgQXVnIDIwMTggMTU6Mjc6NDggKzAwMDAiLCJobWFjIjoieUVSUWpsWFgyU29CTVVpeEsydU9LeUZMSDZWeDdob2E4MHdZOXJiRDlucz0iLCJzYWx0IjoiZWZFWVwvSUpkQWJpNDc0VHRRQ0NqajJ5MUZHQjRCRkZQcGJIbVwvMVF0cHlJPSIsInYiOjJ9",
        "HMAC eyJhY2Nlc3NfdG9rZW4iOiJ4MmdNZUo1TnAwQ2NLcFphditpOWlpWGVRQnRhWU1RXC95ZUV0Y09nWTNKIiwiZGF0ZSI6IkZyaSwgMDMgQXVnIDIwMTggMTU6Mjc6NDggKzAwMDAiLCJobWFjIjoiaUx0c0poT25hWkxIbTgrYU9SWTBzUlFrRjdnVmRxaVFKTzVcL0NYRUQrck09Iiwic2FsdCI6ImVmRVlcL0lKZEFiaTQ3NFR0UUNDamoyeTFGR0I0QkZGUHBiSG1cLzFRdHB5ST0iLCJ2IjoyfQ==",
        "HMAC eyJhY2Nlc3NfdG9rZW4iOiJ4MmdNZUo1TnAwQ2NLcFphditpOWlpWGVRQnRhWU1RXC95ZUV0Y09nWTNKIiwiZGF0ZSI6IkZyaSwgMDMgQXVnIDIwMTggMTU6Mjc6NDggKzAwMDAiLCJobWFjIjoiS0xlWkVJK1R3Qk16ZXBxTGNqXC91anFYcVhEZUFhUndvbmxPcU9XYjZjT2M9Iiwic2FsdCI6ImVmRVlcL0lKZEFiaTQ3NFR0UUNDamoyeTFGR0I0QkZGUHBiSG1cLzFRdHB5ST0iLCJ2IjoyfQ==",
        "HMAC eyJhY2Nlc3NfdG9rZW4iOiJ4MmdNZUo1TnAwQ2NLcFphditpOWlpWGVRQnRhWU1RXC95ZUV0Y09nWTNKIiwiZGF0ZSI6IkZyaSwgMDMgQXVnIDIwMTggMTU6Mjc6NDggKzAwMDAiLCJobWFjIjoidElsRW1vdDNGNm50UzdMRTdWa21BN0hNRVFpenBndVZXZm9MUXY2bnlWbz0iLCJzYWx0IjoiZWZFWVwvSUpkQWJpNDc0VHRRQ0NqajJ5MUZHQjRCRkZQcGJIbVwvMVF0cHlJPSIsInYiOjJ9",
        "HMAC eyJhY2Nlc3NfdG9rZW4iOiJ4MmdNZUo1TnAwQ2NLcFphditpOWlpWGVRQnRhWU1RXC95ZUV0Y09nWTNKIiwiZGF0ZSI6IkZyaSwgMDMgQXVnIDIwMTggMTU6Mjc6NDggKzAwMDAiLCJobWFjIjoiNGlNUDZUMGFVekpwbHczK2IzQUxnMGZBVEtxcHdFUHZrNGcyRDN1bjdxVT0iLCJzYWx0IjoiZWZFWVwvSUpkQWJpNDc0VHRRQ0NqajJ5MUZHQjRCRkZQcGJIbVwvMVF0cHlJPSIsInYiOjJ9"
    )

    init
    {
        var i: Instant = Instant.ofEpochSecond(1533310068)
        this.date = ZonedDateTime.ofInstant(i, ZoneOffset.UTC)
        this.salt = Base64.decode("efEY/IJdAbi474TtQCCjj2y1FGB4BFFPpbHm/1QtpyI=", Base64.DEFAULT)
        this.token = Token(
            "x2gMeJ5Np0CcKpZav+i9iiXeQBtaYMQ/yeEtcOgY3J",
            "LRSEe5zHb1aq20Hr9te2sQF8sLReSkO8bS1eD/9LDM8",
            Base64.decode("f2mTaH9vkZZQyF7SxVeXDlOSDbVwjUzhdXv2T/YYO8k=", Base64.DEFAULT),
            Base64.decode("7v/CdiGoEI7bcj7R2EyDPH5nrCd2+7rHYNACB+Kf2FMx405und2KenGjNpCBPv0jOiptfHJHiY3lldAQTGCdqw==", Base64.DEFAULT),
            ZonedDateTime.now(ZoneOffset.UTC).plusHours(4).toEpochSecond().toDouble()
        )
    }
}