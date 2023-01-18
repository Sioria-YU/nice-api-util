package site.prjct.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Serializable;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

import javax.annotation.Resource;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang.StringUtils;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import site.unp.core.ParameterContext;
import site.unp.core.ZValue;
import site.unp.core.dao.ISqlDAO;
import site.unp.core.service.cs.impl.CommonServiceImpl;
import site.unp.core.util.WebFactory;

/**
 * @author YSY
 * @apiNote NiceAPI를 이용한 본인인증 유틸
 * @since 2022.10.12
 */
@Component
public class NiceApiUtil extends CommonServiceImpl implements Serializable {
    private Logger log = LoggerFactory.getLogger(this.getClass());
    @Resource(name = "SqlDAO")
    private ISqlDAO<ZValue> sqlDAO;
    @Value("${niceapi.access.token}")
    private String NICEAPI_ACCESS_TOKEN;
    @Value("${niceapi.createToken.url}")
    private String CREATE_TOKEN_URL;
    @Value("${niceapi.removeToken.url}")
    private String REMOVE_TOKEN_URL;
    @Value("${niceapi.secretToken.url}")
    private String SECRET_TOKEN_URL;
    @Value("${niceapi.client.id}")
    private String CLIENT_ID;
    @Value("${niceapi.client.secret}")
    private String CLIENT_SECRET;
    @Value("${niceapi.product.id}")
    private String PRODUCT_ID;
    @Value("${niceapi.return.url}")
    private String RETURN_URL;

    /**
     * @param paramCtx
     * @throws Exception
     * @apiNote <pre>
     * 본인인증 페이지를 호출한다.
     * - 본인인증 페이지를 호출하기위한 AccessToken, SecretToken, RequestData 등 필요한 데이터들을 처리하는 method를 사용함.
     * - AccessToken이 없을 경우 토큰을 생성한 후 DB에 저장한다.
     * - Nice인증 완료 후 ReturnUrl을 다른 값으로 하고 싶을 경우 : Param.put niceReturnUrl 값을 설정하면 그 값으로 적용 됨.
     *   단, contextPath는 제외해야함 (ex: /bos/main/main.do)
     * </pre>
     */
    //region NICE API 인증 페이지 로드
    public void callNiceAPIAuthorizationPage(ParameterContext paramCtx) throws Exception {
        boolean isAccessToken = false;
        //properties에 토큰 값을 불러온다.
        if (StringUtils.isNotEmpty(NICEAPI_ACCESS_TOKEN)) {
            isAccessToken = true;
        }//properties에 토큰 설정이 안됐을 경우 db에서 조회한다.
        else if (sqlDAO.findOne("findTop1NiceApi", paramCtx.getParam()) != null) {
            isAccessToken = true;
        }
        //access token이 없을 경우 생성한다.
        if (!isAccessToken) {
            this.createAccessToken(paramCtx);
            if (StringUtils.isNotEmpty(paramCtx.getParam().getString("accessToken"))) {
                sqlDAO.save("saveNiceApi", paramCtx.getParam());
                this.NICEAPI_ACCESS_TOKEN = paramCtx.getParam().getString("accessToken");
            } else {
                throw new NullPointerException();
            }
        }

        //access token으로 secret token을 요청한다.
        this.getSecretToken(paramCtx);
        //요청 데이터 생성
        this.createRequestData(paramCtx);
    }
    //endregion NICE API 인증 페이지 로드

    //region NICE API 인증 프로세스

    /**
     * @param paramCtx - request.session(tokenVersionId(요청시 전송한 토큰 버전), secretKey, initailVector)
     * @return boolean
     * @throws Exception
     * @apiNote <pre>
     * Nice 본인인증 완료 후 처리 프로세스.
     * - 인증 결과 값을 복호화 하여 session에 추가한다.
     * </pre>
     */
    public boolean processNiceAuthorization(ParameterContext paramCtx) throws Exception {
        ZValue param = paramCtx.getParam();
        HttpSession session = paramCtx.getSession();

        String tokenVersionId = param.getString("token_version_id");
        String encData = param.getString("enc_data");
//        String integrityValue = param.getString("integrity_value"); //무결성 값 필요 시 사용

        //복호화키
        ZValue keyInfo = null;
        String secretKey = "";
		if(paramCtx.getSession().getAttribute("secretKey") == null){
			keyInfo  = sqlDAO.findOne("findOneNiceKey", param);

			if(StringUtils.isNotEmpty(keyInfo.getString("key"))) {
				secretKey = keyInfo.getString("key");
//				sqlDAO.deleteOne("deleteNiceKey", keyInfo);
			}else {
				log.info("NiceApi SecretKey is null!!!!!!");
				return false;
			}
		}else {
			secretKey = paramCtx.getSession().getAttribute("secretKey").toString();
		}

        String initailVector = "";
        if(paramCtx.getSession().getAttribute("initailVector") == null ) {
        	initailVector = keyInfo.getString("initailVector");
        }else {
        	initailVector = paramCtx.getSession().getAttribute("initailVector").toString();
        }
        //세션에 등록한 복호화 키 삭제
        paramCtx.getSession().removeAttribute("secretKey");
        paramCtx.getSession().removeAttribute("initailVector");

        //요청번호, 요청 토큰번호 -> 결과 검증용
        String reqNo = "";
        if(paramCtx.getSession().getAttribute("reqNo") == null ) {
        	reqNo = keyInfo.getString("reqNo");
        }else {
        	reqNo = paramCtx.getSession().getAttribute("reqNo").toString();
        }
//        String reqTokenVersionId = paramCtx.getSession().getAttribute("tokenVersionId").toString();
        sqlDAO.deleteOne("deleteNiceKey", param);

        paramCtx.getSession().removeAttribute("reqNo");
        paramCtx.getSession().removeAttribute("tokenVersionId");

        //api 성공여부 확인
        boolean isApiSuccess = false;

        //토큰 버전 검증
//        if (tokenVersionId.equals(reqTokenVersionId)) {
            //복호화 수행
            SecretKey secureKey = new SecretKeySpec(secretKey.getBytes(), "AES");
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.DECRYPT_MODE, secureKey, new IvParameterSpec(initailVector.getBytes()));
            byte[] cipherEnc = Base64.getDecoder().decode(encData);
            String resData = new String(c.doFinal(cipherEnc), "euc-kr");

            if (StringUtils.isNotEmpty(resData)) {
                JSONObject result = (JSONObject) new JSONParser().parse(resData);
                //요청번호 검증
                if (reqNo.equals(result.get("requestno").toString())) {
                    String resultcode = result.get("resultcode") != null ? result.get("resultcode").toString() : "";
                    String requestno = result.get("requestno") != null ? result.get("requestno").toString() : "";
                    String responseno = result.get("responseno") != null ? result.get("responseno").toString() : "";
                    String sitecode = result.get("sitecode") != null ? result.get("sitecode").toString() : "";
                    String enctime = result.get("enctime") != null ? result.get("enctime").toString() : "";
                    String receivedata = result.get("receivedata") != null ? result.get("receivedata").toString() : "";
                    String di = result.get("di") != null ? result.get("di").toString() : "";
                    String ci = result.get("ci") != null ? result.get("ci").toString() : "";
                    String authtype = result.get("authtype") != null ? result.get("authtype").toString() : "";
                    String name = result.get("name") != null ? result.get("name").toString() : "";
                    String utf8Name = result.get("utf8_name") != null ? result.get("utf8_name").toString() : "";
                    String birthdate = result.get("birthdate") != null ? result.get("birthdate").toString() : "";
                    String gender = result.get("gender") != null ? result.get("gender").toString() : "";
                    String mobileNo = result.get("mobileno") != null ? result.get("mobileno").toString() : "";
                    String mobileCo = result.get("mobileco") != null ? result.get("mobileco").toString() : "";
                    String nationalinfo = result.get("nationalinfo") != null ? result.get("nationalinfo").toString() : "";

                    paramCtx.getSession().setAttribute("resultcode", resultcode);   //결과코드
                    paramCtx.getSession().setAttribute("requestno", requestno);     //요청 고유번호
                    paramCtx.getSession().setAttribute("responseno", responseno);   //응답 고유번호
                    paramCtx.getSession().setAttribute("sitecode", sitecode);       //사이트 코드
                    paramCtx.getSession().setAttribute("enctime", enctime);         //암호화 일시
                    paramCtx.getSession().setAttribute("receivedata", receivedata); //요청 시 전달 받은 Receivedata
                    paramCtx.getSession().setAttribute("di", di);                   //개인 식별 코드
                    paramCtx.getSession().setAttribute("ci", ci);                   //개인 식별 코드
                    paramCtx.getSession().setAttribute("authtype", authtype);       //인증 수단
                    paramCtx.getSession().setAttribute("name", name);               //성명
                    paramCtx.getSession().setAttribute("utf8Name", utf8Name);       //UTF-8 암호화 된 성명
                    paramCtx.getSession().setAttribute("birthdate", birthdate);     //생년월일 yyyyMMdd
                    paramCtx.getSession().setAttribute("gender", gender);           //성별 코드
                    paramCtx.getSession().setAttribute("mobileNo", mobileNo);       //휴대폰 번호
                    paramCtx.getSession().setAttribute("mobileCo", mobileCo);       //통신사 구분
                    paramCtx.getSession().setAttribute("nationalinfo", nationalinfo);//내외국인 구분

                    isApiSuccess = true;
                }
            }
//        }
        return isApiSuccess;
    }
    //endregion NICE API 인증 프로세스

    //region NICE API 토큰 폐기

    /**
     * @param paramCtx
     * @throws Exception
     * @apiNote NiceAPI AccessToken을 폐기한다. 현재 AccessToken이 있는 경우에만 가능함.
     */
    public void destroyAccessToken(ParameterContext paramCtx) throws Exception {
        if (StringUtils.isEmpty(NICEAPI_ACCESS_TOKEN)) {
            throw new NullPointerException();
        } else {

            String postData = "";
            Date currentDate = new Date();
            long current_timestamp = currentDate.getTime() / 1000;
            String encodeString = String.format("%s:%s:%s", NICEAPI_ACCESS_TOKEN, String.valueOf(current_timestamp), CLIENT_ID);
            String authorization = Base64.getEncoder().encodeToString(encodeString.getBytes(StandardCharsets.UTF_8));

            URL url = null;
            HttpURLConnection conn = null;

            String responseData = "";
            BufferedReader br = null;
            StringBuffer sb = null;

            try {
                url = new URL(REMOVE_TOKEN_URL);
                conn = (HttpURLConnection) url.openConnection();
                conn.setDoOutput(true);
                conn.setConnectTimeout(5000);
                //헤더 세팅
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
                conn.setRequestProperty("Authorization", "Basic " + authorization);

                try (OutputStream os = conn.getOutputStream()) {
                    os.write(postData.getBytes(StandardCharsets.UTF_8));
                    os.close();
                } catch (IOException e) {
                    log.error(e.toString());
                }

                conn.connect();

                //요청 응답
                br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8));
                sb = new StringBuffer();
                while ((responseData = br.readLine()) != null) {
                    sb.append(responseData); //StringBuffer에 응답받은 데이터 순차적으로 저장
                }

                //http 요청 응답 코드 확인 실시
                String responseCode = String.valueOf(conn.getResponseCode());

                if (responseCode.equals("200")) {
                    JSONObject result = (JSONObject) new JSONParser().parse(sb.toString());
                    JSONObject dataBody = (JSONObject) result.get("dataBody");

                    if ("true".equals(dataBody.get("result").toString())) {
                        ZValue deleteKey = new ZValue();
                        deleteKey.put("accessToken", NICEAPI_ACCESS_TOKEN);
                        if (sqlDao.deleteById("deleteNiceApi", deleteKey) > 0) {
                            log.info("NICE API DestroyAccessToken success");
                        } else {
                            log.info("NICE API DestroyAccessToken Delete fail");
                        }
                    } else {
                        log.info("NICE API DestroyAccessToken fail");
                    }
                }
            } catch (IOException e) {
                log.error(e.toString());
            } finally {
                //http 요청 및 응답 완료 후 BufferedReader를 닫아준다.
                try {
                    if (br != null) {
                        br.close();
                    }
                } catch (IOException e) {
                    log.error(e.toString());
                }
            }
        }
    }
    //endregion NICE API 토큰 폐기

    //region 요청데이터 생성
    protected void createRequestData(ParameterContext paramCtx) throws Exception {
        ZValue param = paramCtx.getParam();

        //rspCd가 P000일 경우에만 성공
        if ("P000".equals(param.getString("rspCd"))) {
            //대칭키를 생성하여 인증 페이지 요청 값을 만들어야 한다.
            //3개 값이 전부 있어야만 대칭키 생성 가능
            if (StringUtils.isNotEmpty(param.getString("reqDtim")) && StringUtils.isNotEmpty(param.getString("reqNo")) && StringUtils.isNotEmpty(param.getString("tokenVal"))) {
                String key = param.getString("reqDtim").trim() + param.getString("reqNo").trim() + param.getString("tokenVal").trim();
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                md.update(key.getBytes());
                byte[] arrHashValue = md.digest();

                String mdKey = Base64.getEncoder().encodeToString(arrHashValue);
                if (mdKey.length() < 32) {
                    throw new IllegalArgumentException();
                }

                //secretKey : 데이터암호화할 대칭키
                //initailVector : 데이터암호화할 Initail Vector
                //hmacKey : 암호화값 위변조 체크용
                String secretKey = mdKey.substring(0, 16);
                String initailVector = mdKey.substring(mdKey.length() - 16);
                String hmacKey = mdKey.substring(0, 32);
                String contextPath = paramCtx.getRequest().getRequestURL().toString().replace(paramCtx.getRequest().getRequestURI(), "");

                // 세션 날아 갔을때 대비 서브용으로 DB 에 secretKey 임시저장
                param.put("subVersionId", UUID.randomUUID().toString().replaceAll("-", ""));

                param.put("key", secretKey);
                param.put("initailVector", initailVector);
                param.put("reqNo", param.getString("reqNo"));

                sqlDAO.save("saveNiceKey", param);


                String returnUrlProps = StringUtils.isNotEmpty(param.getString("nicereturnurl"))? param.getString("nicereturnurl") : RETURN_URL;
                String returnUrl = contextPath + WebFactory.buildUrl(returnUrlProps, param, "menuNo","subVersionId");
//                returnUrl = returnUrl.replace("http://", "https://");

                //요청 데이터 암호화
                JSONObject jsonReqData = new JSONObject();
                jsonReqData.put("requestno", param.getString("reqNo"));
                jsonReqData.put("authtype", "M");
                jsonReqData.put("returnurl", returnUrl);
                jsonReqData.put("sitecode", param.getString("siteCode"));
                jsonReqData.put("methodtype", "get");
                jsonReqData.put("popupyn", "N");

                SecretKey secureKey = new SecretKeySpec(secretKey.getBytes(), "AES");
                Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
                c.init(Cipher.ENCRYPT_MODE, secureKey, new IvParameterSpec(initailVector.getBytes()));
                byte[] encrypted = c.doFinal(jsonReqData.toJSONString().trim().getBytes());
                String encData = Base64.getEncoder().encodeToString(encrypted);
                String integrityValue = Base64.getEncoder().encodeToString(this.hmac256(hmacKey.getBytes(), encData.getBytes()));

                param.put("encData", encData);
                param.put("integrityValue", integrityValue);

                //복호화를 위해 암호키를 세션에 추가함
                paramCtx.getSession().setAttribute("secretKey", secretKey);
                paramCtx.getSession().setAttribute("initailVector", initailVector);


            }
        }
    }
    //endregion 요청데이터 생성

    //region NICE API 토큰 발급
    protected void createAccessToken(ParameterContext paramCtx) throws Exception {
        String postData = "grant_type=client_credentials&scope=default";

        //인증값 생성 규칙 : Authorization = "Basic " + Base64Encoding(client_id:client_secret)
        String encodeString = String.format("%s:%s", CLIENT_ID, CLIENT_SECRET);
        String authorization = Base64.getEncoder().encodeToString(encodeString.getBytes(StandardCharsets.UTF_8));

        URL url = null;
        HttpURLConnection conn = null;

        String responseData = "";
        BufferedReader br = null;
        StringBuffer sb = null;

        try {
            url = new URL(CREATE_TOKEN_URL);
            conn = (HttpURLConnection) url.openConnection();
            conn.setDoOutput(true);
            conn.setConnectTimeout(5000);
            //헤더 세팅
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setRequestProperty("Authorization", "Basic " + authorization);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(postData.getBytes(StandardCharsets.UTF_8));
                os.close();
            } catch (IOException e) {
                log.error(e.toString());
            }

            conn.connect();

            //요청 응답
            br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8));
            sb = new StringBuffer();
            while ((responseData = br.readLine()) != null) {
                sb.append(responseData); //StringBuffer에 응답받은 데이터 순차적으로 저장
            }

            //http 요청 응답 코드 확인 실시
            String responseCode = String.valueOf(conn.getResponseCode());

            if (responseCode.equals("200")) {
                ZValue param = paramCtx.getParam();
                JSONObject result = (JSONObject) new JSONParser().parse(sb.toString());
                JSONObject dataBody = (JSONObject) result.get("dataBody");

                param.put("accessToken", dataBody.get("access_token").toString());
            }
        } catch (IOException e) {
            log.error(e.toString());
        } finally {
            //http 요청 및 응답 완료 후 BufferedReader를 닫아준다.
            try {
                if (br != null) {
                    br.close();
                }
            } catch (IOException e) {
                log.error(e.toString());
            }
        }
    }
    //endregion 본인인증

    //region NICE API SECRET 토큰 발급

    /**
     * @param paramCtx
     * @throws Exception
     * @apiNote 암호화 토큰을 생성한다. NiceAPI 인증 페이즈를 호출하기 위해 반드시 필요함.
     */
    protected void getSecretToken(ParameterContext paramCtx) throws Exception {
        ZValue param = paramCtx.getParam();

        Date currentDate = new Date();
        long current_timestamp = currentDate.getTime() / 1000;

        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyyMMddHHmmss");
        String reqDtim = simpleDateFormat.format(currentDate);
        String reqNo = String.valueOf(currentDate.getTime());
        String encMode = "1";

        //request data setting
        JSONObject dataHeaderParam = new JSONObject();
        dataHeaderParam.put("CNTY_CD", "ko");

        JSONObject dataBodyParam = new JSONObject();
        dataBodyParam.put("req_dtim", reqDtim);
        dataBodyParam.put("req_no", reqNo);
        dataBodyParam.put("enc_mode", encMode);

        JSONObject postData = new JSONObject();
        postData.put("dataHeader", dataHeaderParam);
        postData.put("dataBody", dataBodyParam);

        param.put("reqDtim", reqDtim);
        param.put("reqNo", reqNo);
        param.put("encMode", encMode);

        //인증값 생성 규칙 : Authorization = "bearer " + Base64Encoding(access_token:current_timestamp:client_id)
        String encodeString = String.format("%s:%s:%s", NICEAPI_ACCESS_TOKEN, current_timestamp, CLIENT_ID);
        String authorization = Base64.getEncoder().encodeToString(encodeString.getBytes(StandardCharsets.UTF_8));

        URL url = null;
        HttpURLConnection conn = null;

        String responseData = "";
        BufferedReader br = null;
        StringBuffer sb = null;

        HttpSession session = paramCtx.getSession();

        try {
            url = new URL(SECRET_TOKEN_URL);
//            ignoreSsl();
            conn = (HttpURLConnection) url.openConnection();
            conn.setDoOutput(true);
            conn.setConnectTimeout(5000);
            //헤더 세팅
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Authorization", "bearer " + authorization);
            conn.setRequestProperty("ProductID", PRODUCT_ID);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(postData.toJSONString().getBytes(StandardCharsets.UTF_8));
                os.close();
            } catch (IOException | NullPointerException e) {
                log.error(e.toString());
            }

            conn.connect();

            //요청 응답
            br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8));
            sb = new StringBuffer();
            while ((responseData = br.readLine()) != null) {
                sb.append(responseData); //StringBuffer에 응답받은 데이터 순차적으로 저장
            }

            //http 요청 응답 코드 확인
            String responseCode = String.valueOf(conn.getResponseCode());
            if (responseCode.equals("200")) {
                JSONObject result = (JSONObject) new JSONParser().parse(sb.toString());
                JSONObject dataBody = (JSONObject) result.get("dataBody");

                param.put("rspCd", dataBody.get("rsp_cd"));
                param.put("resMsg", dataBody.get("res_msg"));
                param.put("resultCd", dataBody.get("result_cd"));
                param.put("siteCode", dataBody.get("site_code"));
                param.put("tokenVersionId", dataBody.get("token_version_id"));
                param.put("tokenVal", dataBody.get("token_val"));
                param.put("period", dataBody.get("period"));
                //복호화 검증을 위해 추가
                paramCtx.getSession().setAttribute("tokenVersionId", dataBody.get("token_version_id"));
                paramCtx.getSession().setAttribute("reqNo", reqNo);

            } else {
                log.error("NiceAPI SecretKey Created Failed!!!!");
            }
        } catch (IOException e) {
            log.error(e.toString());
        } finally {
            //http 요청 및 응답 완료 후 BufferedReader를 닫아준다.
            try {
                if (br != null) {
                    br.close();
                }
            } catch (IOException e) {
                log.error(e.toString());
            }
        }


    }
    //endregion NICE API SECRET 토큰 발급

    //region 무결성키 암호화 HMAC256
    protected static byte[] hmac256(byte[] secretKey, byte[] message) {
        byte[] hmac256 = null;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec sks = new SecretKeySpec(secretKey, "HmacSHA256");
            mac.init(sks);
            hmac256 = mac.doFinal(message);
            return hmac256;
        } catch (NullPointerException | NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Failed to generate HMACSHA256 encrypt");
        }
    }
    //endregion 무결성키 암호화

    public static void ignoreSsl() throws Exception{
        HostnameVerifier hv = new HostnameVerifier() {
        public boolean verify(String urlHostName, SSLSession session) {
                return true;
            }
        };
        trustAllHttpsCertificates();
        HttpsURLConnection.setDefaultHostnameVerifier(hv);
    }


    private static void trustAllHttpsCertificates() throws Exception {
        TrustManager[] trustAllCerts = new TrustManager[1];
        TrustManager tm = new miTM();
        trustAllCerts[0] = tm;
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, null);
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
    }

    static class miTM implements TrustManager,X509TrustManager {
        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }

        public boolean isServerTrusted(X509Certificate[] certs) {
            return true;
        }

        public boolean isClientTrusted(X509Certificate[] certs) {
            return true;
        }

        public void checkServerTrusted(X509Certificate[] certs, String authType)
                throws CertificateException {
            return;
        }

        public void checkClientTrusted(X509Certificate[] certs, String authType)
                throws CertificateException {
            return;
        }
    }

}
