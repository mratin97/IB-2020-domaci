package app;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

import org.apache.xml.security.utils.JavaUtils;

import com.google.api.services.gmail.Gmail;
import com.google.api.services.gmail.model.Message;

import keystore.KeyStoreReader;
import model.mailclient.MailBody;
import support.MailHelper;
import support.MailReader;
import util.Base64;
import util.GzipUtil;
import java.util.Base64.Decoder;

public class ReadMailClient extends MailClient {

	public static long PAGE_SIZE = 3;
	public static boolean ONLY_FIRST_PAGE = true;
	
	private static final String KEY_FILE = "./data/session.key";
	private static final String IV1_FILE = "./data/iv1.bin";
	private static final String IV2_FILE = "./data/iv2.bin";
	private static final String KEY_STORE_FILE = "./data/userb.jks";
	private static final String KEY_STORE_PASS = "123";
	private static final String KEY_STORE_PASS_FOR_PRIVATE_KEY = "123";
	private static final String KEY_STORE_ALIAS = "dusan";
	
	private static KeyStoreReader keyStoreReader = new KeyStoreReader();
	public static void main(String[] args) throws IOException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, MessagingException, NoSuchPaddingException, InvalidAlgorithmParameterException {
        // Build a new authorized API client service.
        Gmail service = getGmailService();
        ArrayList<MimeMessage> mimeMessages = new ArrayList<MimeMessage>();
        
        String user = "me";
        String query = "is:unread label:INBOX";
        
        List<Message> messages = MailReader.listMessagesMatchingQuery(service, user, query, PAGE_SIZE, ONLY_FIRST_PAGE);
        for(int i=0; i<messages.size(); i++) {
        	Message fullM = MailReader.getMessage(service, user, messages.get(i).getId());
        	
        	MimeMessage mimeMessage;
			try {
				
				mimeMessage = MailReader.getMimeMessage(service, user, fullM.getId());
				
				System.out.println("\n Message number " + i);
				System.out.println("From: " + mimeMessage.getHeader("From", null));
				System.out.println("Subject: " + mimeMessage.getSubject());
				System.out.println("Body: " + MailHelper.getText(mimeMessage));
				System.out.println("\n");
				
				mimeMessages.add(mimeMessage);
	        
			} catch (MessagingException e) {
				e.printStackTrace();
			}	
        }
        
        System.out.println("Select a message to decrypt:");
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
	        
	    String answerStr = reader.readLine();
	    Integer answer = Integer.parseInt(answerStr);
	    
		MimeMessage chosenMessage = mimeMessages.get(answer);
		//Dekripcija
		String ciphertext=MailHelper.getText(chosenMessage);
		
	    //String[] arryCipher= ciphertext.split(",");
		//MailBody body=new MailBody(arryCipher[0],arryCipher[1],arryCipher[2],arryCipher[3]);
		MailBody body = new MailBody(MailHelper.getText(chosenMessage));
		KeyStore keystore= keyStoreReader.readKeyStore(KEY_STORE_FILE, KEY_STORE_PASS.toCharArray());
		Certificate certificate = keyStoreReader.getCertificateFromKeyStore(keystore, KEY_STORE_ALIAS);
		PrivateKey privateKey = keyStoreReader.getPrivateKeyFromKeyStore(keystore, KEY_STORE_ALIAS, KEY_STORE_PASS_FOR_PRIVATE_KEY.toCharArray());
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] Sessionkey= (cipher.doFinal(body.getEncKeyBytes()));
      
        
        byte[] decodedKey = body.getEncKeyBytes();
        SecretKey originalKey= new SecretKeySpec(Sessionkey, "AES");
        
        //TODO: Decrypt a message and decompress it. The private key is stored in a file.
		Cipher aesCipherDec = Cipher.getInstance("AES/CBC/PKCS5Padding");
		//SecretKey secretKey = new SecretKeySpec(JavaUtils.getBytesFromFile(KEY_FILE), "AES");
		byte[] iv1 = body.getIV1Bytes();
		
		//byte[] iv1 = JavaUtils.getBytesFromFile(IV1_FILE);
		IvParameterSpec ivParameterSpec1 = new IvParameterSpec(iv1);
		aesCipherDec.init(Cipher.DECRYPT_MODE, originalKey, ivParameterSpec1);
		
		//String str = MailHelper.getText(chosenMessage);
		byte[] bodyEnc = aesCipherDec.doFinal(Base64.decode(body.getEncMessage()));
		
		String receivedBodyTxt = new String(bodyEnc);
		
		String body1 = new String(aesCipherDec.doFinal(Base64.decode(body.getEncMessage())));
		String decompressedBodyText = GzipUtil.decompress(Base64.decode(body1));
		System.out.println("Body text: " + decompressedBodyText);
		
		
		//byte[] iv2 = JavaUtils.getBytesFromFile(IV2_FILE);
		byte[] iv2 = body.getIV1Bytes();
		IvParameterSpec ivParameterSpec2 = new IvParameterSpec(iv2);
		//inicijalizacija za dekriptovanje
		
		aesCipherDec.init(Cipher.DECRYPT_MODE, originalKey, ivParameterSpec2);
		aesCipherDec.init(Cipher.DECRYPT_MODE, originalKey, ivParameterSpec1);
		
		//dekompresovanje i dekriptovanje subject-a
		String decryptedSubjectTxt = new String(aesCipherDec.doFinal(Base64.decode(chosenMessage.getSubject())));
		String decompressedSubjectTxt = GzipUtil.decompress(Base64.decode(decryptedSubjectTxt));
		System.out.println("Subject text: " + new String(decompressedSubjectTxt));
		
	}
}
