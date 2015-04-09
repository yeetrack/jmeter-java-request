package com.yeetrack.jmeter.java;

import org.apache.commons.codec.binary.Base64;
import org.apache.jmeter.config.Arguments;
import org.apache.jmeter.protocol.java.sampler.AbstractJavaSamplerClient;
import org.apache.jmeter.protocol.java.sampler.JavaSamplerContext;
import org.apache.jmeter.samplers.SampleResult;

/**
 * Created by Xuemeng Wang on 14-9-18.
 */
public class QianbaoPerformanceJmeter extends AbstractJavaSamplerClient {
    private SampleResult sampleResult;

    @Override
    public SampleResult runTest(JavaSamplerContext javaSamplerContext) {
        String params = javaSamplerContext.getParameter("params");
        String key = javaSamplerContext.getParameter("private-key");
        String plain = javaSamplerContext.getParameter("plain");
        sampleResult = new SampleResult();
        sampleResult.setSampleLabel("sign");
        sampleResult.sampleStart();
        String resultSign = Common.getHMAC(params, plain).substring(0,16);

        String threeDesResult = null;

        RSA rsa = new RSA();
        try {
            rsa.loadPublicKey(key);
            byte[] bytes = rsa.encrypt(rsa.getPublicKey(), plain.getBytes());
            threeDesResult = new String(Base64.encodeBase64(bytes));
        } catch (Exception e) {
            e.printStackTrace();
        }
        //System.out.println("key--->"+threeDesResult);

        sampleResult.setResponseData("{\"params\": \""+params+"\", \"key\": \""+threeDesResult+"\", \"hmac\": \""+resultSign+"\"}", "utf-8");
        //sampleResult.setResponseData("Hello", "utf-8");
        sampleResult.setResponseCodeOK();
        sampleResult.setSuccessful(true);
        sampleResult.sampleEnd();

        return sampleResult;
    }

    @Override
    public void setupTest(JavaSamplerContext context) {


    }

    @Override
    public void teardownTest(JavaSamplerContext context) {
        super.teardownTest(context);
    }

    @Override
    public Arguments getDefaultParameters() {
        Arguments params = new Arguments();
        params.addArgument("params", "params");
        params.addArgument("private-key", "key");
        params.addArgument("plain", "24key");
        return params;
    }
}
