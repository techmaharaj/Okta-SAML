# SAML2.0 Demo with Okta - Python Application

### Prerequisites

- Python 3.x
- Flask
- pysaml2
- Okta Developer Account

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/sudhanshu456/python-saml2-okta-demo.git
   ```

2. Install the required dependencies:

   ```bash
   pip install -r requirements.txt
   ```

### Configuration

1. Create signing certificate and place them in `conf/sp_cert.pem` and `conf/sp_key.pem`, respectively.
   ```
   openssl req -x509 -nodes -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365
   ```
2. Create Okta Account, and follow [these steps](https://help.okta.com/en-us/content/topics/apps/apps_app_integration_wizard_saml.htm) to register the application and get the metadata file. 
3. Place your IdP metadata in this location `conf/idp-metadata.xml`
4. For Single Logout Service, follow [these steps](https://developer.okta.com/docs/guides/single-logout/saml2/main/#configure-slo). 

### Running the Application

1. Run the Flask application:

   ```bash
   python main.py
   ```

2. Access the application at `https://localhost:8443`

### Enabling Debug Mode

```bash
python main.py --debug
```