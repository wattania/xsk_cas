// wti
package com.xsk;
 
import java.sql.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.servlet.http.HttpServletRequest;
import org.jasig.cas.web.support.WebUtils;
import org.springframework.webflow.execution.RequestContext;
import org.jasig.cas.authentication.principal.Credentials;
import java.util.Date;
import java.sql.Timestamp;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class DatabaseLogger {
    
    public static String TABLE_AUTH_            = "user_auth";
    public static String FIELD_AUTH_USERNAME    = "auth_username";
    public static String FIELD_AUTH_PASSWORD    = "auth_password";
    public static String FIELD_AUTH_UPDATE_TIME = "update_time";
    
    public static String TABLE_LOGIN_LOG        = "login_log";
    public static String FIELD_LOGIN_USERNAME   = "login_username";
    public static String FIELD_LOGIN_CLIENT_IP  = "login_client_ip";
    public static String FIELD_LOGIN_ACTION     = "login_action";
    public static String FIELD_LOGIN_DATE       = "login_date";
    
    //wti
    private String jdbcUrl;
    private String driverClass;
    private String user;
    private String password;  
    
    protected Logger logger = LoggerFactory.getLogger(getClass());
     
    public void authStore(String aUsername, String aPassword){
        Date today = new Date();
        Timestamp ts = new Timestamp(today.getTime());
        Connection conn = null;
        try {
            Class.forName(this.driverClass);
            conn = DriverManager.getConnection(this.jdbcUrl, this.user, this.password);
            int total = getUsernameRecord(conn, aUsername);
 
            String newHash = DatabaseLogger.getHash(aPassword);
            if(total > 0){
                // update password
                
                if(IsPasswordChange(conn, aUsername, newHash))
                {
                    updateNewPassword(conn, aUsername, newHash, ts);
                }
            }else{
                // insert username + password
                insertNewPassword(conn, aUsername, newHash, ts);
            }
            
            conn.close(); 
            
        } catch (ClassNotFoundException cnfe) {
            this.logger.debug("Couldn't find the driver!");
            this.logger.debug("Let's print a stack trace, and exit.");
            cnfe.printStackTrace();
            
        } catch (SQLException se) {
            this.logger.debug("Couldn't connect: print out a stack trace and exit.");
            se.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        
    }
    
    public static String getHash(String aString)
        throws NoSuchAlgorithmException {
        String input = aString + "277fcfa40cffc9cd4fc739efb4eac42447dc359e";
        MessageDigest md = null;
        md = MessageDigest.getInstance("SHA-1");
    
        byte[] mdbytes = md.digest(input.getBytes());
        String result = "";
        for (int i=0; i < mdbytes.length; i++) {
            result +=
                  Integer.toString( ( mdbytes[i] & 0xff ) + 0x100, 16).substring( 1 );
        }
        return result;
    }
    
    private boolean IsPasswordChange(Connection aConn, String aUsername, String aPasswordHash)
        throws SQLException {
        Connection conn = aConn;
        String query = "SELECT " + FIELD_AUTH_PASSWORD + " FROM " + TABLE_AUTH_ + " WHERE " + FIELD_AUTH_USERNAME + " =?";
		PreparedStatement pstmt = conn.prepareStatement(query);
		pstmt.setString(1, aUsername);

		ResultSet rs = pstmt.executeQuery();

		String hash = "";
		while (rs.next()) {
			hash = rs.getString(FIELD_AUTH_PASSWORD);
			break;
		}
		pstmt.close();
         
        if(aPasswordHash.equals(hash))
        {
            return false;
        }
        
        return true;
    }
    private int insertNewPassword(Connection aConn, String aUsername, String aPassword, Timestamp aTs)
        throws SQLException {
        Connection conn = aConn;
        String query = "INSERT INTO " + TABLE_AUTH_ + " (" + FIELD_AUTH_USERNAME + ", " + FIELD_AUTH_PASSWORD + ", " + FIELD_AUTH_UPDATE_TIME + ") VALUES (?, ?, ?)";
        PreparedStatement pstmt = conn.prepareStatement(query);
        pstmt.setString(1, aUsername);
        pstmt.setString(2, aPassword);
        pstmt.setTimestamp(3, aTs);
        
        int a = pstmt.executeUpdate();
        pstmt.close();
        return a;
    }
    
    private int updateNewPassword(Connection aConn, String aUsername, String aPassword, Timestamp aTs)
        throws SQLException {
        Connection conn = aConn;
        String query = "UPDATE "+TABLE_AUTH_+" SET "+FIELD_AUTH_PASSWORD+" =?, "+FIELD_AUTH_UPDATE_TIME+" =? WHERE "+FIELD_AUTH_USERNAME+" =?";
        PreparedStatement pstmt = conn.prepareStatement(query);
        pstmt.setString(1, aPassword);
        pstmt.setTimestamp(2, aTs);
        pstmt.setString(3, aUsername);

        int a = pstmt.executeUpdate();
        pstmt.close();
        return a;
    }
    
    private int getUsernameRecord(Connection aConn, String aUsername)
			throws SQLException {
		Connection conn = aConn;
		String query = "SELECT "+FIELD_AUTH_USERNAME+" FROM "+TABLE_AUTH_+" WHERE "+FIELD_AUTH_USERNAME+" =?";

		PreparedStatement pstmt = conn.prepareStatement(query);

		pstmt.setString(1, aUsername);

		ResultSet rs = pstmt.executeQuery();

		int count = 0;
        
		while (rs.next()) {
            count = count + 1;
			String a = rs.getString(FIELD_AUTH_USERNAME);
		}
		pstmt.close();
		return count;
	}
    
    public void writeLog(String aUsername, RequestContext aContext, String aAction)
    {
        Date today = new Date();
        Timestamp ts = new Timestamp(today.getTime());
        
        HttpServletRequest request = WebUtils.getHttpServletRequest(aContext);
        String remoetIp = request.getRemoteAddr();
        this.logger.debug("Database Logger ->  USERNAME :" + aUsername);
        this.logger.debug("Database Logger ->  CLIENTIP :" + remoetIp);
        this.logger.debug("Database Logger ->  ACTION   :" + aAction);
       
        
        Connection conn = null;
        
        
        try {
            Class.forName(this.driverClass);
            conn = DriverManager.getConnection(this.jdbcUrl, this.user, this.password);
            String query = "INSERT INTO "+TABLE_LOGIN_LOG+" ("+FIELD_LOGIN_USERNAME+", "+FIELD_LOGIN_CLIENT_IP+", "+FIELD_LOGIN_ACTION+", "+FIELD_LOGIN_DATE+") VALUES (?, ?, ?, ?)";
            PreparedStatement pstmt = conn.prepareStatement(query);
            pstmt.setString(1, aUsername);
            pstmt.setString(2, remoetIp);
            pstmt.setString(3, aAction);
            pstmt.setTimestamp(4, ts);
            
            int a = pstmt.executeUpdate();
            pstmt.close();
            conn.close(); 
            
        } catch (ClassNotFoundException cnfe) {
            this.logger.debug("Couldn't find the driver!");
            this.logger.debug("Let's print a stack trace, and exit.");
            cnfe.printStackTrace();
            
        } catch (SQLException se) {
            this.logger.debug("Couldn't connect: print out a stack trace and exit.");
            se.printStackTrace();
        }
 
    }
    
    public final void setJdbcUrl(final String aJdbcUrl) {
        this.logger.debug("Set JDBC URL: " + aJdbcUrl);
        this.jdbcUrl = aJdbcUrl;
    }
    
    public final void setDriverClass(final String aDriverClass) {
        this.logger.debug("Set DriverClass: " + aDriverClass);
        this.driverClass = aDriverClass;
    }
    
    public final void setUser(final String aUser) {
        this.logger.debug("Set User: " + aUser);
        this.user = aUser;
    }
    
    public final void setPassword(final String aPassword) {
        this.logger.debug("Set Password: " + aPassword);
        this.password = aPassword;
    }
}