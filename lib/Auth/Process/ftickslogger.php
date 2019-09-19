<?php
include ('/var/www/config.php');
/**
 * F-TICKS logger Authentication Processing filter
 *
 * @author Tamas Frank <sitya@niif.hu>
 * @package simpleSAMLphp
 * @version $Id$
 */
class sspmod_ftickslogger_Auth_Process_ftickslogger extends SimpleSAML_Auth_ProcessingFilter
{

/**
	 * The attribute to log
	 */
	private $attribute = NULL;
	private $secretsalt = NULL;

	private $typeTag = 'FTICKS/IdPnube/1.0/';

	/**
	 * Initialize this filter.
	 *
	 * @param array $config  Configuration information about this filter.
	 * @param mixed $reserved  For future use.
	 */
	public function __construct($config, $reserved) {
		parent::__construct($config, $reserved);

		assert('is_array($config)');

		if (array_key_exists('attributename', $config)) {
			$this->attribute = $config['attributename'];
			if (!is_string($this->attribute)) {
				throw new Exception('Invalid attribute name given to fticklogger filter.');
			}
		}

		if (array_key_exists('secretsalt', $config)) {
			$this->secretsalt = $config['secretsalt'];
			if (!is_string($this->secretsalt)) {
				throw new Exception('Invalid secretsalt given to fticklogger filter.');
			}
		}

	}


	/**
	 * Log line.
	 *
	 * @param array &$state  The current state.
	 */
	public function process(&$state) {
		assert('is_array($state)');
		assert('array_key_exists("Attributes", $state)');

		$TS = time();
		$AP = 'NA';
		$RP = 'NA';
		$PN = 'NA';
		$AM = 'urn:oasis:names:tc:SAML:2.0:ac:classes:Password';

		if (array_key_exists($this->attribute, $state['Attributes'])) {
			$PN = hash('sha256', $state['Attributes'][$this->attribute][0] . $this->secretsalt);
		}
		if (array_key_exists('Source', $state)) {
				$AP = $state['Source']['entityid'];
		}

		//TODO: get RP from $state['saml:RequesterID'] array
		// check if it's defined
		// check if it's an array
		// get the last of the values in the array
		if (array_key_exists('Destination', $state)) {
			if(empty($state['saml:RequesterID']))
			{
				$RP = $state['Destination']['entityid'];
			}
			else
			{
				$longitud = sizeof($state['saml:RequesterID']);
				$RP = $state['saml:RequesterID'][$longitud-1];
			}
		}

		//Nos conectamos a la base de datos a la tabla de los fticks para guardar los datos
		$conn = new mysqli(HOST, USER, PASS, DDBB);
		// Check connection
		if ($conn->connect_error) {
    			echo "Error en la base de datos";
    			die("Connection failed: " . $conn->connect_error);
		}

		$TSNuevo = date('Y-m-d H:i:s',$TS);
		$sql = "INSERT INTO " .TABLAESTADISTICAS. " (uid,TS,AP,RP,PN,AM) VALUES (NULL,'$TSNuevo','$AP','$RP','$PN','$AM')";
		$result = $conn->query($sql);



		SimpleSAML_Logger::stats($this->typeTag . '#TS=' . $TS . '#AP=' . $AP . '#RP=' . $RP . '#PN=' . $PN . '#AM=' . $AM . '#');
	}

}
