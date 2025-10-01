import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Base64;

public class DigitalSteganographer extends JFrame {

    // A unique separator to distinguish the filename from the file data
    private static final String FILENAME_SEPARATOR = "::FILENAME_SEPARATOR::";

    private static final String DB_URL = "jdbc:mysql://localhost:3306/steganography_db";
    private static final String DB_USER = "your_db_user";
    private static final String DB_PASSWORD = "your_db_password";

    private JPasswordField passwordField;
    private JLabel imagePathLabel;
    private JLabel documentPathLabel;
    private File selectedImageFile;
    private File selectedDocumentFile;

    public DigitalSteganographer() {
        setTitle("Digital Steganographer - File Hider");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(600, 400);
        setLocationRelativeTo(null);
        setLayout(new BorderLayout(10, 10));

        JPanel mainPanel = new JPanel();
        mainPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        mainPanel.setLayout(new BorderLayout(10, 10));

        JPanel formPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);

        // Row 0: Select Document
        gbc.gridx = 0;
        gbc.gridy = 0;
        JButton selectDocumentButton = new JButton("Select Document to Hide");
        formPanel.add(selectDocumentButton, gbc);

        gbc.gridx = 1;
        gbc.gridy = 0;
        documentPathLabel = new JLabel("No document selected.");
        formPanel.add(documentPathLabel, gbc);
        
        // Row 1: Select Image
        gbc.gridx = 0;
        gbc.gridy = 1;
        JButton selectImageButton = new JButton("Select Cover Image");
        formPanel.add(selectImageButton, gbc);

        gbc.gridx = 1;
        gbc.gridy = 1;
        imagePathLabel = new JLabel("No image selected.");
        formPanel.add(imagePathLabel, gbc);

        // Row 2: Password
        gbc.gridx = 0;
        gbc.gridy = 2;
        formPanel.add(new JLabel("Password:"), gbc);

        gbc.gridx = 1;
        gbc.gridy = 2;
        passwordField = new JPasswordField();
        formPanel.add(passwordField, gbc);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 0));
        JButton encodeButton = new JButton("Encode Document");
        JButton decodeButton = new JButton("Decode Document");
        buttonPanel.add(encodeButton);
        buttonPanel.add(decodeButton);

        mainPanel.add(formPanel, BorderLayout.CENTER);
        mainPanel.add(buttonPanel, BorderLayout.SOUTH);

        add(mainPanel);

        selectDocumentButton.addActionListener(e -> selectDocument());
        selectImageButton.addActionListener(e -> selectImage());
        encodeButton.addActionListener(e -> process(true));
        decodeButton.addActionListener(e -> process(false));

        DatabaseManager.init();
    }
    
    private void selectDocument() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Select a Document to Hide");
        int result = fileChooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            selectedDocumentFile = fileChooser.getSelectedFile();
            documentPathLabel.setText(selectedDocumentFile.getName());
        }
    }

    private void selectImage() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("Image files", "png", "bmp"));
        int result = fileChooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            selectedImageFile = fileChooser.getSelectedFile();
            imagePathLabel.setText(selectedImageFile.getName());
        }
    }

    private void process(boolean isEncode) {
        if (selectedImageFile == null) {
            JOptionPane.showMessageDialog(this, "Please select a cover image first.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        String password = new String(passwordField.getPassword());
        if (password.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Password cannot be empty.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        if (isEncode) {
            if (selectedDocumentFile == null) {
                JOptionPane.showMessageDialog(this, "Please select a document to hide.", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            encodeImage(password);
        } else {
            decodeImage(password);
        }
    }

    private void encodeImage(String password) {
        try {
            // Read the document file into a byte array
            byte[] documentBytes = Files.readAllBytes(selectedDocumentFile.toPath());
            // Convert the byte array to a Base64 string
            String documentBase64 = Base64.getEncoder().encodeToString(documentBytes);

            // Create the payload with filename and data
            String payload = selectedDocumentFile.getName() + FILENAME_SEPARATOR + documentBase64;

            BufferedImage originalImage = ImageIO.read(selectedImageFile);
            String encryptedPayload = CryptoCore.encrypt(payload, password);
            BufferedImage stegoImage = StegoCore.embed(originalImage, encryptedPayload);

            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setDialogTitle("Save Stego Image");
            fileChooser.setSelectedFile(new File("stego-image.png"));
            int userSelection = fileChooser.showSaveDialog(this);

            if (userSelection == JFileChooser.APPROVE_OPTION) {
                File fileToSave = fileChooser.getSelectedFile();
                ImageIO.write(stegoImage, "png", fileToSave);
                JOptionPane.showMessageDialog(this, "Document hidden successfully!", "Success", JOptionPane.INFORMATION_MESSAGE);
                DatabaseManager.logOperation("ENCODE", selectedImageFile.getAbsolutePath(), fileToSave.getAbsolutePath(), (int)selectedDocumentFile.length());
                passwordField.setText("");
            }
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Encoding failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            ex.printStackTrace();
        }
    }

    private void decodeImage(String password) {
        try {
            BufferedImage stegoImage = ImageIO.read(selectedImageFile);
            String encryptedPayload = StegoCore.extract(stegoImage);
            String decryptedPayload = CryptoCore.decrypt(encryptedPayload, password);

            // Split the payload to get the filename and the Base64 data
            String[] parts = decryptedPayload.split(FILENAME_SEPARATOR, 2);
            if (parts.length != 2) {
                throw new IllegalStateException("Invalid data format. Filename separator not found.");
            }
            String originalFilename = parts[0];
            String documentBase64 = parts[1];

            // Decode the Base64 string back to the original file bytes
            byte[] documentBytes = Base64.getDecoder().decode(documentBase64);

            // Ask the user where to save the extracted file
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setDialogTitle("Save Extracted Document");
            fileChooser.setSelectedFile(new File(originalFilename));
            int userSelection = fileChooser.showSaveDialog(this);

            if (userSelection == JFileChooser.APPROVE_OPTION) {
                File fileToSave = fileChooser.getSelectedFile();
                try (FileOutputStream fos = new FileOutputStream(fileToSave)) {
                    fos.write(documentBytes);
                }
                JOptionPane.showMessageDialog(this, "Document extracted successfully!", "Success", JOptionPane.INFORMATION_MESSAGE);
                DatabaseManager.logOperation("DECODE", selectedImageFile.getAbsolutePath(), fileToSave.getAbsolutePath(), documentBytes.length);
            }
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Decoding failed. Check password or image integrity.", "Error", JOptionPane.ERROR_MESSAGE);
            ex.printStackTrace();
        }
    }

    // --- StegoCore, CryptoCore, and DatabaseManager classes remain unchanged ---
    // (They are included here for completeness)

    private static class StegoCore {
        private static final int STEGO_MARKER = 0x5A5A5A5A;

        public static BufferedImage embed(BufferedImage image, String data) {
            byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
            int dataLength = dataBytes.length;
            int capacity = (image.getWidth() * image.getHeight() * 3) / 2;
            if (dataLength + 8 > capacity) {
                throw new IllegalArgumentException("Message is too large for the selected image.");
            }

            BufferedImage newImage = new BufferedImage(image.getWidth(), image.getHeight(), BufferedImage.TYPE_INT_ARGB);
            newImage.getGraphics().drawImage(image, 0, 0, null);

            byte[] stegoMarkerBytes = ByteBuffer.allocate(4).putInt(STEGO_MARKER).array();
            byte[] lengthBytes = ByteBuffer.allocate(4).putInt(dataLength).array();

            byte[] payload = new byte[stegoMarkerBytes.length + lengthBytes.length + dataBytes.length];
            System.arraycopy(stegoMarkerBytes, 0, payload, 0, stegoMarkerBytes.length);
            System.arraycopy(lengthBytes, 0, payload, stegoMarkerBytes.length, lengthBytes.length);
            System.arraycopy(dataBytes, 0, payload, stegoMarkerBytes.length + lengthBytes.length, dataBytes.length);

            int payloadIndex = 0;
            int nibbleIndex = 0;

            for (int y = 0; y < image.getHeight() && payloadIndex < payload.length; y++) {
                for (int x = 0; x < image.getWidth() && payloadIndex < payload.length; x++) {
                    int pixel = newImage.getRGB(x, y);
                    int alpha = (pixel >> 24) & 0xFF;
                    int red = (pixel >> 16) & 0xFF;
                    int green = (pixel >> 8) & 0xFF;
                    int blue = pixel & 0xFF;

                    if (payloadIndex < payload.length) {
                        red = embedNibble(red, payload[payloadIndex], nibbleIndex++);
                        if (nibbleIndex > 1) {
                            nibbleIndex = 0;
                            payloadIndex++;
                        }
                    }
                    if (payloadIndex < payload.length) {
                        green = embedNibble(green, payload[payloadIndex], nibbleIndex++);
                        if (nibbleIndex > 1) {
                            nibbleIndex = 0;
                            payloadIndex++;
                        }
                    }
                    if (payloadIndex < payload.length) {
                        blue = embedNibble(blue, payload[payloadIndex], nibbleIndex++);
                        if (nibbleIndex > 1) {
                            nibbleIndex = 0;
                            payloadIndex++;
                        }
                    }

                    int newPixel = (alpha << 24) | (red << 16) | (green << 8) | blue;
                    newImage.setRGB(x, y, newPixel);
                }
            }
            return newImage;
        }

        private static int embedNibble(int color, byte data, int nibbleIndex) {
            int nibble = (nibbleIndex == 0) ? (data >> 4) & 0x0F : data & 0x0F;
            return (color & 0xF0) | nibble;
        }

        public static String extract(BufferedImage image) {
            byte[] headerBytes = new byte[8];
            int byteIndex = 0;
            int nibbleIndex = 0;
            byte currentByte = 0;

            for (int y = 0; y < image.getHeight() && byteIndex < 8; y++) {
                for (int x = 0; x < image.getWidth() && byteIndex < 8; x++) {
                    int pixel = image.getRGB(x, y);

                    if (byteIndex < 8) {
                        currentByte = assembleByte(currentByte, (pixel >> 16) & 0xFF, nibbleIndex++);
                        if (nibbleIndex > 1) {
                            headerBytes[byteIndex++] = currentByte;
                            currentByte = 0;
                            nibbleIndex = 0;
                        }
                    }
                    if (byteIndex < 8) {
                        currentByte = assembleByte(currentByte, (pixel >> 8) & 0xFF, nibbleIndex++);
                        if (nibbleIndex > 1) {
                            headerBytes[byteIndex++] = currentByte;
                            currentByte = 0;
                            nibbleIndex = 0;
                        }
                    }
                    if (byteIndex < 8) {
                        currentByte = assembleByte(currentByte, pixel & 0xFF, nibbleIndex++);
                        if (nibbleIndex > 1) {
                            headerBytes[byteIndex++] = currentByte;
                            currentByte = 0;
                            nibbleIndex = 0;
                        }
                    }
                }
            }

            int marker = ByteBuffer.wrap(headerBytes, 0, 4).getInt();
            if (marker != STEGO_MARKER) {
                throw new IllegalStateException("No hidden message found (invalid stego marker).");
            }

            int dataLength = ByteBuffer.wrap(headerBytes, 4, 4).getInt();
            if (dataLength <= 0 || dataLength > (long) image.getWidth() * image.getHeight() * 3 / 2) {
                throw new IllegalStateException("Invalid data length detected.");
            }

            byte[] dataBytes = new byte[dataLength];
            byteIndex = 0;
            nibbleIndex = 0;
            currentByte = 0;
            
            int startPixelIndex = (8 * 2) / 3;
            int channelsToSkip = (8 * 2) % 3;

            for (int i = startPixelIndex; i < (long) image.getWidth() * image.getHeight() && byteIndex < dataLength; i++) {
                int x = i % image.getWidth();
                int y = i / image.getWidth();
                int pixel = image.getRGB(x, y);

                int red = (pixel >> 16) & 0xFF;
                int green = (pixel >> 8) & 0xFF;
                int blue = pixel & 0xFF;

                // Process Red channel, but skip it for the start pixel if the header used it
                if (!(i == startPixelIndex && channelsToSkip >= 1)) {
                    if (byteIndex < dataLength) {
                        currentByte = assembleByte(currentByte, red, nibbleIndex++);
                        if (nibbleIndex > 1) { dataBytes[byteIndex++] = currentByte; currentByte = 0; nibbleIndex = 0; }
                    }
                }
                
                // Process Green channel, but skip it for the start pixel if the header used it
                if (!(i == startPixelIndex && channelsToSkip >= 2)) {
                    if (byteIndex < dataLength) {
                        currentByte = assembleByte(currentByte, green, nibbleIndex++);
                        if (nibbleIndex > 1) { dataBytes[byteIndex++] = currentByte; currentByte = 0; nibbleIndex = 0; }
                    }
                }
                
                // Process Blue channel (always processed)
                if (byteIndex < dataLength) {
                    currentByte = assembleByte(currentByte, blue, nibbleIndex++);
                    if (nibbleIndex > 1) { dataBytes[byteIndex++] = currentByte; currentByte = 0; nibbleIndex = 0; }
                }
            }
            return new String(dataBytes, StandardCharsets.UTF_8);
        }

        private static byte assembleByte(byte currentByte, int color, int nibbleIndex) {
            int nibble = color & 0x0F;
            if (nibbleIndex == 0) {
                return (byte) (nibble << 4);
            } else {
                return (byte) (currentByte | nibble);
            }
        }
    }

    private static class CryptoCore {
        private static final String ALGORITHM = "AES/GCM/NoPadding";
        private static final int TAG_LENGTH_BIT = 128;
        private static final int IV_LENGTH_BYTE = 12;
        private static final int SALT_LENGTH_BYTE = 16;

        public static String encrypt(String plainText, String password) throws Exception {
            byte[] salt = getRandomNonce(SALT_LENGTH_BYTE);
            byte[] iv = getRandomNonce(IV_LENGTH_BYTE);

            SecretKey aesKey = getAESKeyFromPassword(password.toCharArray(), salt);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(TAG_LENGTH_BIT, iv));

            byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
            byte[] cipherTextWithIvSalt = ByteBuffer.allocate(salt.length + iv.length + cipherText.length)
                    .put(salt)
                    .put(iv)
                    .put(cipherText)
                    .array();

            return Base64.getEncoder().encodeToString(cipherTextWithIvSalt);
        }

        public static String decrypt(String cText, String password) throws Exception {
            byte[] decode = Base64.getDecoder().decode(cText.getBytes(StandardCharsets.UTF_8));
            ByteBuffer bb = ByteBuffer.wrap(decode);

            byte[] salt = new byte[SALT_LENGTH_BYTE];
            bb.get(salt);
            byte[] iv = new byte[IV_LENGTH_BYTE];
            bb.get(iv);
            byte[] cipherText = new byte[bb.remaining()];
            bb.get(cipherText);

            SecretKey aesKey = getAESKeyFromPassword(password.toCharArray(), salt);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(TAG_LENGTH_BIT, iv));

            byte[] plainText = cipher.doFinal(cipherText);
            return new String(plainText, StandardCharsets.UTF_8);
        }

        private static byte[] getRandomNonce(int numBytes) {
            byte[] nonce = new byte[numBytes];
            new SecureRandom().nextBytes(nonce);
            return nonce;
        }

        private static SecretKey getAESKeyFromPassword(char[] password, byte[] salt)
                throws NoSuchAlgorithmException, InvalidKeySpecException {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password, salt, 65536, 256);
            return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        }
    }

    private static class DatabaseManager {
        public static void init() {
            try {
                Class.forName("com.mysql.cj.jdbc.Driver");
            } catch (ClassNotFoundException e) {
                System.err.println("MySQL JDBC Driver not found. Add it to your classpath.");
            }
        }

        public static void logOperation(String type, String originalPath, String stegoPath, int messageLength) {
            String sql = "INSERT INTO operations_log (operation_type, original_image_path, stego_image_path, message_length, timestamp) VALUES (?, ?, ?, ?, ?)";
            try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
                 PreparedStatement pstmt = conn.prepareStatement(sql)) {

                pstmt.setString(1, type);
                pstmt.setString(2, originalPath);
                pstmt.setString(3, stegoPath);
                pstmt.setInt(4, messageLength);
                pstmt.setTimestamp(5, new Timestamp(System.currentTimeMillis()));
                pstmt.executeUpdate();

            } catch (SQLException e) {
                System.err.println("Database logging failed: " + e.getMessage());
            }
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (Exception e) {
                e.printStackTrace();
            }
            new DigitalSteganographer().setVisible(true);
        });
    }
}

