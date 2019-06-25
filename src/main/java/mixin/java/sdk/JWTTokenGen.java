package mixin.java.sdk;

import java.security.MessageDigest;
import java.security.interfaces.RSAPrivateKey;
import java.util.Date;
import java.util.UUID;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

import org.apache.commons.codec.binary.Hex;

/**
 * JWTTokenGen
 */
public class JWTTokenGen {

    /**
     * get token
     * @param uri
     * @param body
     * @param pkey
     * @param appid
     * @param sessionid
     * @return
     */
    public static String genToken(String uri, String body, RSAPrivateKey pkey, String appid, String sessionid) {
        return genToken("GET", uri, body, UUID.randomUUID().toString(), pkey, appid, sessionid);
    }

    /**
     * 完全自定义
     * @param method
     * @param uri
     * @param body
     * @param pkey
     * @param appid
     * @param sessionid
     * @return
     */
    public static String genToken(String method, String uri, String body, RSAPrivateKey pkey, String appid,
            String sessionid) {
        return genToken(method, uri, body, UUID.randomUUID().toString(), pkey, appid, sessionid);
    }

    /**
     * 
     * @param method
     * @param uri
     * @param body
     * @param jti
     * @param pkey
     * @param appid
     * @param sessionid
     * @return
     */
    private static String genToken(String method, String uri, String body, String jti, RSAPrivateKey pkey, String appid,
            String sessionid) {
        String sig = genSig(method, uri, body);
        long ts = System.currentTimeMillis();
        String token = JWT.create().withClaim("uid", appid).withClaim("sid", sessionid).withIssuedAt(new Date(ts))
                .withExpiresAt(new Date(ts + 12 * 60 * 60 * 1000L)).withClaim("sig", sig).withClaim("jti", jti)
                .sign(Algorithm.RSA512(null, pkey));
        return token;
    }

    /**
     * 
     * @param method
     * @param uri
     * @param body
     * @return
     */
    private static String genSig(String method, String uri, String body) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return Hex.encodeHexString(md.digest((method + uri + body).getBytes()));
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
            return null;
        }
    }
}