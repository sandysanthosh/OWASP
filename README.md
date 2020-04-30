# OWASP
Web Security Tools &amp; Methods


    We cannot  firewall  or  patch  our way to secure Websites. Security professionals used to think that firewalls, Secure Sockets Layer (SSL), patching, and privacy policies were enough. Today, however, these methods are outdated and ineffective, as attacks on prominent, well-protected Websites are occurring every day. Citigroup, PBS, Sega, Nintendo, Gawker, AT&T, the CIA, the US Senate, NASA, the NYSE, Zynga, and thousands of others have something in common: all of them have had Websites compromised in the last year.


 # Top 10 java defenses for website security:

# owasp cheat-sheet

# 1.query parametized;

    antomy of a sql

    anatomy of a sql injection Attack;

    query parameterization in java:

                string name = request.getParameter("newName");
                string id = request.getParameter("id");

                preparedStatement pstmr = con.preparedstatement("update employees set 
                name=? where id= ?");
                pstmt.setStringO( 1 , newName);
                pstmt.setString( 2, id);


# 2. password storage:

      store password based on need:

            use a  salt( de-duplication)
            SCRYPT/PBKDF2(slow, peroformance hit,easy)
            HMAC(require good key storage, tough)

1.do not limit the type of characters or length of user password

2.use a cryptographically strong credentials-sepcific salt

                    protect([salt]+[password]);
                use a 32 char or 64 char salt
                do not depend on hiding,spitting

 # 3a) impose difficult verification on the attack(strong/fast)

                 HMAC-SHA-256[(private key],[salt]+[password])

 # 3b) impose difficult verification on attack and defender

                PBKDF 2 when  FIPS certification
                scrypt where resisting any/all hardware

                XSS defense cross site scripting:

                no third party libraries
                more complete api


html contexts
xml contexts	

 # web page built in java JSP is a vulnerable to XSS:

            solution:

1)

        <input type="text" name="data" value="<%= Encode.forHthmlAttribute(datavalue)%"/>

2)

      <textarea name="text"><%= Encode.forHtmlContect(textValue) %"/>

3)

      <button
      onclick="alert('<%= Encode.forJavascriptAttribute(alertMsg) %>');
      click me
      </button>

4)

          <script type="text/javascript">
          var msg="<%= Encode.forJavascriptBlock(message) %>";
          alert*msg);
          </script>


 # html sanitization


 # code google owasp java html sanitization

 # Bean Validation:

    Fields
    Properties
    Classes

    @Constraints 

    (@Pattern, @Digits, @Min, @Max, @Size, @Past, @Future, @CreditCardNumber, @Email, @URL, etc.)
    
                  @Size(min = 10, max = 500)
                  private String message;
                  @Past
                  private Date birthDate;
                  @Pattern(regexp = "[a-zA-Z0-9 ]", message="article.title.error")
                  private String articleTitle;
                  
              
 # Implementing input validation:
  
 # Credinital and PII information:
 
       https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html
  
      <input type="text" spellcheck="false" autocomplete="off" autocorrect="off" autocapitalize="off"></input>

            spellcheck="false"
            autocomplete="off"
            autocorrect="off"
            autocapitalize="off"
            
   # WebSocket implementation hints:
   
                Access filtering through the "Origin" HTTP request header
                Input / Output validation
                Authentication
                Authorization
                Access token explicit invalidation
                Confidentiality and Integrity
  
  



<a href="http://starwalt.in/Blogs/index.html">Follow us on Blog</a>

