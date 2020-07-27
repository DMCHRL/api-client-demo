package utils;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;

public class Main {

    private static final String privateKey = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAJL0ZIyvqNWqdE/d6s/KmZ5A05XMKa1/F/WBpThIKuNJGhCGiYlGX0nzxI//uHpXzESzALJ3RvC5CHRth2HDHMsp/Y3nrRDbLBwlmimaP9cZ9acIhsW3vsDssSUJPHVoasQue3PjN+32dCdfzUn8D/07nUCl+y+hOYQISNJzZ2VJAgMBAAECgYEAiiPemTlO9ntjFui/IFGNEmxR+VCQJR2BwjD6xOtiFYHUVJCDnV1fmb7imZKDMc5yoGm8UAc70nG9duS3DLlCyGWQPPyKdLdPPInjO9a+DGiIn/u2MEnVXe9bsXMl3+2JqHzGkkjkxoldgD6y9xko2G2W/d1RLnjdDtr1aEbj0AECQQD/672epfQagk5VPx/oZfqVDPw2dLY3KiMfCBQ/R6t2Hb7BzUUtTJt7YINuYbzDKD6jdrEoMq8nr/XRBI1NymcBAkEAkwAGqx12nn05nBCD7mVwFbA511KC7HUJOg1spUIXmPPLpT+G6owwnyVRuyMBv6Q2Rwnyy/e1YbIDmUJYXEYGSQJBAM9+w28t/oy/ueNEGwrCJDlVHejJGDQB5hfy5PeplEtgMpnPZJcl1apixi1o8TMKHj9KrLh636i98gBWQHsh8AECQBvbHmhgrfC8pCUZ0BZl7IZ/nYZbIWozh2sTzinGy3f1gvqufh+GL1SJGuLOcG9ja9GsZfEW4K1BsYLiWqIpttkCQBvkR7VzRQ12f910DbgWBVz4XuH0LZmJ1sAK51mUdgJDqvI/++S6BY1gzgOGm4hTm1xckK3cSLT/6Ovhm/FPg4I=";
    private static final String accessKey = "demo";
    private static final String url = "http://localhost:8080/rSASign";
    public static void main(String[] args) {
        Map<String,String> params = new HashMap<>(16);
        params.put("accessKey",accessKey);
        params.put("param1","hello");
        long timestemp = LocalDateTime.now().toInstant(ZoneOffset.of("+8")).toEpochMilli();
        params.put("timestemp",String.valueOf(timestemp));
        params.put("nonce","123456");
        String data = RSAUitil.mapToString(params);
        // 签名
        String sign = RSAUitil.sign(data,privateKey);
        params.put("sign",sign);
        data = RSAUitil.mapToString(params);
        // 加密
        String body = RSAUitil.encrypt(data, privateKey);
        String requestParams = "{" +
                "\"accessKey\": \"" + accessKey + "\"," +
                "\"body\": \"" + body + "\"" +
                "}";
        System.out.println(RequestUtil.post(url, requestParams));

    }
}
