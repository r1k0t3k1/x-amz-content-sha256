package XAmzContentSha256;

import static burp.api.montoya.http.handler.RequestToBeSentAction.continueWith;
import static burp.api.montoya.http.handler.ResponseReceivedAction.continueWith;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;


class CustomHttpHandler implements HttpHandler {
    private final String SIGN_HEADER = "x-amz-content-sha256";

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        Annotations annotations = requestToBeSent.annotations();
        
        if (requestToBeSent.hasHeader(SIGN_HEADER)) {
            ByteArray body = requestToBeSent.body();
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

            HttpRequest modifiedRequest = requestToBeSent.withHeader(SIGN_HEADER, headerValue);
            return continueWith(modifiedRequest, annotations);
        } else {
            return continueWith(requestToBeSent, annotations);
        }
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        Annotations annotations = responseReceived.annotations();
        return continueWith(responseReceived, annotations);
    }
}
