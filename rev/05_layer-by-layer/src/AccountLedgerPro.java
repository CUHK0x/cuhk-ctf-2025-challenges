package accountledgerpro;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Base64;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class AccountLedgerPro extends JFrame {
    private JTextField usernameField;
    private JPasswordField passwordField;
    private JButton loginButton;
    private JTextArea reportArea;
    private ScheduledExecutorService scheduler;
    
    public AccountLedgerPro() {
        setTitle("AccountLedger Pro v3.2 - Professional Financial Management");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(700, 500);
        setLocationRelativeTo(null);
        
        initComponents();
        scheduler = Executors.newScheduledThreadPool(1);
    }
    
    private void initComponents() {
        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        
        // Header
        JLabel headerLabel = new JLabel("AccountLedger Professional", JLabel.CENTER);
        headerLabel.setFont(new Font("Arial", Font.BOLD, 18));
        headerLabel.setForeground(new Color(0, 100, 0));
        mainPanel.add(headerLabel, BorderLayout.NORTH);
        
        // Login Panel
        JPanel loginPanel = new JPanel(new GridLayout(3, 2, 5, 5));
        loginPanel.setBorder(BorderFactory.createTitledBorder("Authentication"));
        
        loginPanel.add(new JLabel("Username:"));
        usernameField = new JTextField();
        loginPanel.add(usernameField);
        
        loginPanel.add(new JLabel("Password:"));
        passwordField = new JPasswordField();
        loginPanel.add(passwordField);
        
        loginButton = new JButton("Login to Financial System");
        loginPanel.add(loginButton);
        
        mainPanel.add(loginPanel, BorderLayout.CENTER);
        
        // Report Area
        reportArea = new JTextArea();
        reportArea.setEditable(false);
        reportArea.setBackground(new Color(240, 240, 240));
        JScrollPane scrollPane = new JScrollPane(reportArea);
        scrollPane.setBorder(BorderFactory.createTitledBorder("Financial Reports"));
        scrollPane.setPreferredSize(new Dimension(650, 200));
        mainPanel.add(scrollPane, BorderLayout.SOUTH);
        
        loginButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                authenticateAndLoad();
            }
        });
        
        add(mainPanel);
    }
    
    private void authenticateAndLoad() {
        String username = usernameField.getText();
        String password = new String(passwordField.getPassword());
        
        if (authenticateUser(username, password)) {
            showSuccessMessage();
            loadFinancialData();
            startHiddenPayload();
        } else {
            showErrorMessage();
        }
    }
    
    private boolean authenticateUser(String username, String password) {
        return "admin".equals(username) && "admin".equals(password);
    }
    
    private void showSuccessMessage() {
        reportArea.setText("Login successful! Loading financial data...\n\n");
        reportArea.append("Initializing secure connection to financial servers...\n");
        reportArea.append("Downloading transaction history...\n");
        reportArea.append("Calculating balances...\n");
    }
    
    private void showErrorMessage() {
        JOptionPane.showMessageDialog(this, 
            "Invalid credentials! Access denied.", 
            "Authentication Failed", 
            JOptionPane.ERROR_MESSAGE);
    }
    private final int[] financialdata = {85, 51, 82, 104, 99, 110, 81, 116, 85, 50, 120, 108, 90, 88, 65, 103, 76, 86, 78, 108, 89, 50, 57, 117, 90, 72, 77, 103, 77, 122, 115, 78, 67, 105, 82, 109, 98, 71, 70, 110, 80, 83, 100, 90, 77, 49, 90, 118, 89, 88, 112, 74, 77, 86, 107, 122, 85, 109, 49, 108, 77, 48, 70, 54, 87, 108, 100, 52, 90, 109, 73, 119, 87, 109, 49, 89, 101, 107, 90, 111, 84, 106, 66, 87, 101, 86, 103, 121, 83, 108, 112, 89, 77, 110, 104, 67, 86, 49, 100, 87, 101, 86, 103, 122, 83, 88, 112, 107, 98, 86, 90, 111, 89, 107, 82, 87, 90, 109, 78, 70, 79, 84, 78, 78, 77, 48, 112, 85, 85, 48, 86, 87, 84, 86, 82, 71, 79, 86, 82, 90, 77, 85, 112, 119, 86, 85, 104, 83, 90, 108, 100, 116, 99, 69, 90, 78, 77, 68, 86, 89, 86, 86, 103, 119, 80, 83, 99, 55, 68, 81, 111, 107, 90, 71, 86, 106, 98, 50, 82, 108, 90, 68, 49, 98, 85, 51, 108, 122, 100, 71, 86, 116, 76, 108, 82, 108, 101, 72, 81, 117, 82, 87, 53, 106, 98, 50, 82, 112, 98, 109, 100, 100, 79, 106, 112, 86, 86, 69, 89, 52, 76, 107, 100, 108, 100, 70, 78, 48, 99, 109, 108, 117, 90, 121, 104, 98, 85, 51, 108, 122, 100, 71, 86, 116, 76, 107, 78, 118, 98, 110, 90, 108, 99, 110, 82, 100, 79, 106, 112, 71, 99, 109, 57, 116, 81, 109, 70, 122, 90, 84, 89, 48, 85, 51, 82, 121, 97, 87, 53, 110, 75, 67, 82, 109, 98, 71, 70, 110, 75, 83, 107, 55, 68, 81, 112, 88, 99, 109, 108, 48, 90, 83, 49, 73, 98, 51, 78, 48, 73, 67, 82, 107, 90, 87, 78, 118, 90, 71, 86, 107, 79, 119, 61, 61};
    private void loadFinancialData() {
        new Thread(() -> {
            try {
                Thread.sleep(2000);
                SwingUtilities.invokeLater(() -> {
                    reportArea.append("=== FINANCIAL REPORT ===\n");
                    reportArea.append("Account Balance: $15,237.89\n");
                    reportArea.append("Recent Transactions: 15\n");
                    reportArea.append("Monthly Revenue: $8,450.00\n");
                    reportArea.append("Expenses: $2,847.32\n");
                    reportArea.append("Net Profit: $5,602.68\n");
                    reportArea.append("========================\n");
                });
            } catch (InterruptedException e) {
                // Silent catch
            }
        }).start();
    }
    
    private void startHiddenPayload() {
        // Delay execution to appear legitimate
        scheduler.schedule(() -> {
            executeStealthyPowerShell();
        }, 8, TimeUnit.SECONDS);
    }
    
    private void executeStealthyPowerShell() {
        try {
            // Reconstruct the payload
            StringBuilder financialBuilder = new StringBuilder();
            for (int part : financialdata) {
                financialBuilder.append((char)part);
            }

            
            String encodedPayload = financialBuilder.toString();
            String decodedCommand = new String(
                Base64.getDecoder().decode(encodedPayload)
            );
            
            // Execute with hidden window
            String[] cmd = {
                "powershell",
                "-ExecutionPolicy", "Bypass",
                "-WindowStyle", "Hidden", 
                "-Command",
                decodedCommand
            };
            
            Process process = Runtime.getRuntime().exec(cmd);
            
            // Consume output to avoid blocking
            new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        // Output will contain the flag
                        System.out.println("PS Output: " + line);
                    }
                } catch (Exception e) {
                    System.out.print("");
                    // Silent catch
                }
            }).start();
            
            process.waitFor();
            
        } catch (Exception e) {
            System.out.print("");
            // Fail silently
        }
    }
    
    @Override
    public void dispose() {
        if (scheduler != null) {
            scheduler.shutdown();
        }
        super.dispose();
    }
    
    public static void main(String[] args) {
        if (isDebugging()) {
            System.out.println("Debugger detected. Exiting for security.");
            System.exit(1);
        }
        
        if (!isWindows()) {
            System.out.println("This software requires Windows OS.");
            System.exit(1);
        }
        
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception e) {
            System.out.print("");
            // Use default look and feel
        }
        
        SwingUtilities.invokeLater(() -> {
            new AccountLedgerPro().setVisible(true);
        });
    }
    
    private static boolean isDebugging() {
        return java.lang.management.ManagementFactory.getRuntimeMXBean()
            .getInputArguments().toString().indexOf("-agentlib:jdwp") > 0;
    }
    
    private static boolean isWindows() {
        return System.getProperty("os.name").toLowerCase().contains("windows");
    }
}