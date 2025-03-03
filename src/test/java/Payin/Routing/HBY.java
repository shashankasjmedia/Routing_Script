package Payin.Routing;

import java.io.*;
import java.util.zip.CRC32;
import java.util.zip.CheckedInputStream;
import java.util.logging.Logger;

public class HBY {
    private static final Logger LOGGER = Logger.getLogger(HBY.class.getName());

    public static long getChecksumCRC32(InputStream stream, int bufferSize) throws IOException {
        CheckedInputStream checkedInputStream = new CheckedInputStream(stream, new CRC32());
        byte[] buffer = new byte[bufferSize];
        while (checkedInputStream.read(buffer, 0, buffer.length) >= 0) {
            // Read in chunks
        }
        long checksum = checkedInputStream.getChecksum().getValue();
        LOGGER.info("Checksum: " + checksum);
        return checksum;
    }

    public static void main(String[] args) {
        // Simulating transaction object
        Transaction transaction = new Transaction();

        // Concatenating transaction details
        String checksumStr = transaction.getMid() + transaction.getTxnId() + transaction.getOrderNo() + transaction.getTxnStatus();

        // Creating InputStream from the string
        try (InputStream targetStream = new ByteArrayInputStream(checksumStr.getBytes())) {
            long checksum = getChecksumCRC32(targetStream, checksumStr.length());
            System.out.println("CRC32 Checksum: " + checksum);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

// Mock Transaction class for demonstration
class Transaction {
  

    public String getMid() {
        return "TXN67890";
    }

    public String getTxnId() {
        return "TXN67890";
    }

    public String getOrderNo() {
        return "TXN67890";
    }

    public String getTxnStatus() {
        return "TXN67890";
    }
}
