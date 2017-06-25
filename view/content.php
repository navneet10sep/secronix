    <div class="container" style="margin-top: 80px;">

      <div class="row row-offcanvas row-offcanvas-right">

        <div class="col-xs-12 col-sm-9">
          <p class="pull-right visible-xs">
            <button type="button" class="btn btn-primary btn-xs" data-toggle="offcanvas">Toggle nav</button>
          </p>
          <div class="jumbotron">
            <h3 style='font-weight: bold;'>
A Developer Driven Automated Secure Code Review tool using Pattern, Attack and Audit based detection techniques to identify, asses and remediate Security Vulnerabilities throughout the Web Application Development Phase
</h3>
            <p>This website demostrate detection and reporting techniques to automate the process of bug detection during development phase  </p>
          </div>
          <div class="row">
            <div class="col-xs-6 col-lg-4">
              <h2>SQL Injection</h2>
              <p>SQL Injection is a code injection technique, used to attack data-driven applications, in which nefarious SQL statements are inserted into an entry field for execution (e.g. to dump the database contents to the attacker).</p>
              <p><a class="btn btn-default" href="<?=$this->baseUrl?>?&action=view&page=sqlinjection"> Demo &raquo;</a></p>
            </div><!--/.col-xs-6.col-lg-4-->
            <div class="col-xs-6 col-lg-4">
              <h2>XSS</h2>
              <p>oss-Site Scripting (XSS) attacks are a type of injection, in which malicious scripts are injected into otherwise benign and trusted web sites. XSS attacks occur when an attacker uses a web application to send malicious code, generally in the form of a browser side script, to a different end user</p>
              <p><a class="btn btn-default" href="<?=$this->baseUrl?>?&action=view&page=xssinjection" role="button"> Demo &raquo;</a></p>
            </div><!--/.col-xs-6.col-lg-4-->
 
          </div><!--/row-->
        </div><!--/.col-xs-12.col-sm-9-->

 
      </div><!--/row-->

      <hr>

      <footer>
        <p>&copy; 2016 Company, Inc.</p>
      </footer>

    </div><!--/.container-->
