/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package XAmzContentSha256;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;


//Burp will auto-detect and load any class that extends BurpExtension.
public class Extension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("X-Amz-Content-Sha256");

        api.http().registerHttpHandler(new CustomHandler());
    }
}
