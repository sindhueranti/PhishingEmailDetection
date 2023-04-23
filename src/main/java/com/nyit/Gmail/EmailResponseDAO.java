package com.nyit.Gmail;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;


public class EmailResponseDAO {

    public static void insertEmailResponseData(EmailResponse emailResponse) throws SQLException {

        try { 
        	
            final String SQL_INSERT = "INSERT INTO EMAILRESPONSE (SPFVALUE, DKIMVALUE, DMARCVALUE, URLSTATUS, EMAILSTATUS) VALUES (?,?,?,?,?)";
       	
            String dbURL = "jdbc:oracle:thin:@localhost:1521/XEPDB1";
            String username = "PEDAPPUSER";
            String password = "EMail@1234";
            Class.forName("oracle.jdbc.driver.OracleDriver");
            Connection connection = DriverManager.getConnection(dbURL, username, password);
            if (connection != null) {
                System.out.println("Successfully connected to Database");
            }

            PreparedStatement preparedStatement = connection.prepareStatement(SQL_INSERT);
            preparedStatement.setString(1, emailResponse.getIsValidSPF());
            preparedStatement.setString(2, emailResponse.getIsValidDKIM());
            preparedStatement.setString(3, emailResponse.getIsValidDmarc());
            String urlStatus = emailResponse.getPositivePer()>3 ? "Malicious" : "Clean";
            preparedStatement.setString(4, urlStatus);
            preparedStatement.setString(5, emailResponse.getEmailValidationResult());

           int row = preparedStatement.executeUpdate();

            // rows affected
            System.out.println(row);
            connection.close();

        } catch (Exception e) {
            System.out.println(e);
        }       
    }
}