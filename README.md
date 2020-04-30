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
  
  # Top 10 Web Application Security Risks
  
 # Injection.
     Injection flaws, such as SQL, NoSQL, OS, and LDAP injection, occur when untrusted data is sent to an interpreter as part of a command or query. The attacker’s hostile data can trick the interpreter into executing unintended commands or accessing data without proper authorization.
 
 # Broken Authentication.
             Application functions related to authentication and session management are often implemented incorrectly, allowing attackers to compromise passwords, keys, or session tokens, or to exploit other implementation flaws to assume other users’ identities temporarily or permanently.
             
 # Sensitive Data Exposure.
     Many web applications and APIs do not properly protect sensitive data, such as financial, healthcare, and PII. Attackers may steal or modify such weakly protected data to conduct credit card fraud, identity theft, or other crimes. Sensitive data may be compromised without extra protection, such as encryption at rest or in transit, and requires special precautions when exchanged with the browser.

 # XML External Entities (XXE).
         Many older or poorly configured XML processors evaluate external entity references within XML documents. External entities can be used to disclose internal files using the file URI handler, internal file shares, internal port scanning, remote code execution, and denial of service attacks.
         
 # Broken Access Control. 
     Restrictions on what authenticated users are allowed to do are often not properly enforced. Attackers can exploit these flaws to access unauthorized functionality and/or data, such as access other users’ accounts, view sensitive files, modify other users’ data, change access rights, etc.
     
 # Security Misconfiguration. 
        Security misconfiguration is the most commonly seen issue. This is commonly a result of insecure default configurations, incomplete or ad hoc configurations, open cloud storage, misconfigured HTTP headers, and verbose error messages containing sensitive information. Not only must all operating systems, frameworks, libraries, and applications be securely configured, but they must be patched/upgraded in a timely fashion.
        
 # Cross-Site Scripting XSS. 
        XSS flaws occur whenever an application includes untrusted data in a new web page without proper validation or escaping, or updates an existing web page with user-supplied data using a browser API that can create HTML or JavaScript. XSS allows attackers to execute scripts in the victim’s browser which can hijack user sessions, deface web sites, or redirect the user to malicious sites.

 # Insecure Deserialization. 
    Insecure deserialization often leads to remote code execution. Even if deserialization flaws do not result in remote code execution, they can be used to perform attacks, including replay attacks, injection attacks, and privilege escalation attacks.
    Using Components with Known Vulnerabilities. Components, such as libraries, frameworks, and other software modules, run with the same 

 # privileges as the application. 
        If a vulnerable component is exploited, such an attack can facilitate serious data loss or server takeover. Applications and APIs using components with known vulnerabilities may undermine application defenses and enable various attacks and impacts.

 # Insufficient Logging & Monitoring. 
         Insufficient logging and monitoring, coupled with missing or ineffective integration with incident response, allows attackers to further attack systems, maintain persistence, pivot to more systems, and tamper, extract, or destroy data. Most breach studies show time to detect a breach is over 200 days, typically detected by external parties rather than internal processes or monitoring.




<a href="http://starwalt.in/Blogs/index.html">Follow us on Blog</a>

