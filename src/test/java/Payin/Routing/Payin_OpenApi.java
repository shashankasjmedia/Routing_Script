package Payin.Routing;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Random;
import java.util.Base64;
import java.util.Date;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.testng.annotations.Test;
import org.json.JSONObject;
import org.testng.annotations.*;
import com.google.gson.JsonObject;
import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.response.Response;

public class Payin_OpenApi {

    String baseurl = "https://payinpg.starpg.co/api/v1/payin-transaction-merchant/";

    @BeforeMethod
    public void beforeMethod() {
        RestAssured.baseURI = baseurl;
    }

    private String generateHash(JsonObject data, String salt) {
        StringBuilder sb = new StringBuilder();

        // ✅ Null checks to avoid errors
        sb.append(getSafeValue(data, "currency_name"));
        sb.append(getSafeValue(data, "amount"));
        sb.append(getSafeValue(data, "mobile_no"));
        sb.append(getSafeValue(data, "email"));
        sb.append(getSafeValue(data, "merchant_ref"));
        sb.append(getSafeValue(data, "prod_desc"));
        sb.append(getSafeValue(data, "payin_type"));
        sb.append(getSafeValue(data, "name"));
        sb.append(getSafeValue(data, "upi_id"));
        sb.append(salt);

        return sha256(sb.toString());
    }

    private String getSafeValue(JsonObject data, String key) {
        return (data.has(key) && !data.get(key).isJsonNull()) ? data.get(key).getAsString() : "";
    }

    private String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                hexString.append(String.format("%02x", b));
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void Direct_Transfer() {
        JsonObject data = new JsonObject();
        JsonObject dataObject = new JsonObject();
        Random random = new Random();

        String merchantRef = "Auto" + new SimpleDateFormat("yyyyMMddHHmmss").format(new Date()) 
                            + String.format("%03d", random.nextInt(1000));

        dataObject.addProperty("currency_name", "INR");
        dataObject.addProperty("amount", String.valueOf(random.nextInt(10) + 10));
        dataObject.addProperty("mobile_no", "987636789");
        dataObject.addProperty("email", "sus2i@mail.com");
        dataObject.addProperty("merchant_ref", merchantRef);
        dataObject.addProperty("prod_desc", "NKIM");
        dataObject.addProperty("payin_type", "INTENT");
        dataObject.addProperty("name", "Shan");
        dataObject.addProperty("upi_id", "test@upi"); // ✅ Fixed potential null UPI ID

        String salt = "2661e8d5f56f23aa0e5ae987"; 
        String generatedHash = generateHash(dataObject, salt);

        data.add("data", dataObject);
        data.addProperty("hash", generatedHash);

        Response response = RestAssured.given()
                                       .contentType(ContentType.JSON)
                                       .header("API-KEY", "9b433105a12f")
                                       .body(data.toString())
                                       .when()
                                       .post(baseurl);

        System.out.println("Response: " + response.asString());
        System.out.println("Generated Hash: " + generatedHash);

        // ✅ Check if response is null or empty before extracting INTENT
        if (response.getBody() != null && response.getBody().asString().trim().length() > 0) {
            String intentValue = response.jsonPath().getString("INTENT");

            if (intentValue != null && !intentValue.isEmpty()) {
                System.out.println("Extracted INTENT: " + intentValue);

                // Try Base64 decoding
                try {
                    String decodedIntent = new String(Base64.getDecoder().decode(intentValue));
                    System.out.println("✅ Base64 Decoded INTENT: " + decodedIntent);
                } catch (IllegalArgumentException e) {
                    System.out.println("❌ Base64 decoding failed. Trying AES decryption...");
                }

                // Try AES decryption if Base64 fails
                try {
                    String apiKey = "9b433105a12f";
                    String hashKey = "2661e8d5f56f23aa0e5ae987";
                    String secretKey = CryptoUtils.hashGenerator(apiKey, hashKey);

                    String decryptedIntent = CryptoUtils.decryptPayload(intentValue, secretKey);
                    JSONObject jsonObj = new JSONObject(decryptedIntent);
                    String upiPayQr = jsonObj.getString("UPI_PAY_QR");

                    System.out.println("Decrypted UPI_PAY_QR: " + upiPayQr);
                } catch (Exception e) {
                    System.out.println("❌ AES decryption failed. Check key/IV.");
                }
            } else {
                System.out.println("❌ INTENT value is null or empty in the response!");
            }
        } else {
            System.out.println("❌ Response body is null or empty!");
        }

        // Validate Response
    }
}

// CryptoUtils class (Integrated into the same file)
class CryptoUtils {

    public static String hashGenerator(String apiKey, String hashKey) {
        String combinedString = apiKey + hashKey;
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = sha256.digest(combinedString.getBytes("UTF-8"));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString().toUpperCase();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] setKey(String secretKey) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            byte[] key = secretKey.getBytes("UTF-8");
            sha.update(key);
            return sha.digest();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String decryptPayload(String responseString, String encryptKey) {
        try {
            byte[] secretKey = setKey(encryptKey);
            SecretKeySpec keySpec = new SecretKeySpec(secretKey, 0, 16, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
            byte[] decodedBytes = Base64.getDecoder().decode(responseString);
            byte[] decryptedBytes = cipher.doFinal(decodedBytes);
            return new String(decryptedBytes, "UTF-8");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
