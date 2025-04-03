package XAmzContentSha256;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;


class CustomProxyHandler implements ProxyRequestHandler {
    private final String SIGN_HEADER = "x-amz-content-sha256";

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
        var annotations = interceptedRequest.annotations();
        return ProxyRequestReceivedAction.continueWith(interceptedRequest, annotations);
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        Annotations annotations = interceptedRequest.annotations();
        if (interceptedRequest.hasHeader(SIGN_HEADER)) {
            ByteArray body = interceptedRequest.body();
            String headerValue = "";

            try {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] hash = md.digest(body.getBytes());
                headerValue = String.format("%064x", new BigInteger(1, hash));
                annotations = annotations.withNotes("Request was a modified.\nSignHeader value: " + headerValue);
            } catch (NoSuchAlgorithmException e) {
                // ここには到達しないはず
            } catch (Exception e) {

            }

            HttpRequest modifiedRequest = interceptedRequest.withHeader(SIGN_HEADER, headerValue);
            return ProxyRequestToBeSentAction.continueWith(modifiedRequest);
        }
        return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
    }

}
