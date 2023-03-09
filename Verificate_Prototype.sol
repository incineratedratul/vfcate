pragma solidity ^0.8.0;


//import "ipfs-core/0.8.0";


contract CertificateVerificationSystem
{


    // Define the four stakeholders: applicant, admin, company, university
    address public applicant;
    address public admin;
    address public company;
    address public university;


    // Mapping to store the applicant details
    mapping (address => Applicant) public applicants;


    // Mapping to store the verified certificates
    mapping (address => mapping (bytes32 => Certificate)) public verifiedCertificates;


    // Struct to hold applicant details
    struct Applicant
    {
        bool registered;
        bool verified;
        address[] allowedCompanies;
        bytes32[] certificateHashes;
    }


    // Struct to hold certificate details
    struct Certificate
    {
        bytes32 hash;
        bool verifiedByAdmin;
        bool verifiedByUniversity;
        address[] allowedCompanies;
    }


    // Event to notify when certificate is verified
    event CertificateVerified(address indexed applicant, bytes32 indexed certificateHash);


    // Event to notify when company requests access
    event CompanyRequestedAccess(address indexed applicant, address indexed company);


    // Event to notify when company is granted access
    event CompanyGrantedAccess(address indexed applicant, address indexed company);


    // Event to notify when university approves certificate
    event UniversityApprovedCertificate(address indexed applicant, bytes32 indexed certificateHash);


    // Constructor to initialize stakeholders
    constructor()
    {
        applicant = msg.sender;
        admin = address(0);
        company = address(0);
        university = address(0);
    }


    // Modifier to check if the caller is the applicant
    modifier onlyApplicant()
    {
        require(msg.sender == applicant, "Only the applicant can call this function");
        _;
    }


    // Modifier to check if the caller is the admin
    modifier onlyAdmin()
    {
        require(msg.sender == admin, "Only the admin can call this function");
        _;
    }


    // Modifier to check if the caller is the company
    modifier onlyCompany()
    {
        require(msg.sender == company, "Only the company can call this function");
        _;
    }


    // Modifier to check if the caller is the university
    modifier onlyUniversity()
    {
        require(msg.sender == university, "Only the university can call this function");
        _;
    }


    // Function for applicant to register themselves
    function register() public
    {
        require(!applicants[msg.sender].registered, "Applicant already registered");
        applicants[msg.sender].registered = true;
    }


    // Function for applicant to login
    function login() public onlyApplicant
    {
        require(applicants[msg.sender].registered, "Applicant not registered");
        applicant = msg.sender;
    }


    // Function for admin to verify certificate
    function verifyCertificate(address _applicant, bytes32 _certificateHash) public onlyAdmin
    {
        require(applicants[_applicant].registered, "Applicant not registered");
        verifiedCertificates[_applicant][_certificateHash].verifiedByAdmin = true;
        emit CertificateVerified(_applicant, _certificateHash);
    }


    // Function for university to approve certificate
    function approveCertificate(address _applicant, bytes32 _certificateHash) public onlyUniversity
    {
        require(applicants[_applicant].registered, "Applicant not registered");
        verifiedCertificates[_applicant][_certificateHash].verifiedByUniversity = true;
        emit UniversityApprovedCertificate(_applicant, _certificateHash);
    }


    function uploadCertificate(bytes32 _certificateHash) public onlyApplicant
    {
    require(applicants[msg.sender].registered, "Applicant not registered");
    require(!verifiedCertificates[msg.sender][_certificateHash].verifiedByAdmin, "Certificate already verified");


    // Add certificate to the verifiedCertificates mapping
    verifiedCertificates[msg.sender][_certificateHash].hash = _certificateHash;


    // Notify the admin to verify the certificate
    emit CertificateVerified(msg.sender, _certificateHash);
    }


    // Function for admin to notify applicant that certificate is verified
function notifyVerifiedCertificate(address _applicant, bytes32 _certificateHash) public onlyAdmin {
    require(applicants[_applicant].registered, "Applicant not registered");
    require(verifiedCertificates[_applicant][_certificateHash].verifiedByAdmin, "Certificate not verified by admin");


    // Set the verified flag for the applicant
    applicants[_applicant].verified = true;
}


// Function for applicant to approve access to a company
function approveCompanyAccess(address _company) public onlyApplicant
{
    require(applicants[msg.sender].registered, "Applicant not registered");
    require(applicants[msg.sender].verified, "Applicant not verified");


    // Add the company to the allowed companies list
    applicants[msg.sender].allowedCompanies.push(_company);


    // Notify the company that access has been granted
    emit CompanyGrantedAccess(msg.sender, _company);
}


// Function for company to request access to view a certificate
function requestCertificateAccess(address _applicant, bytes32 _certificateHash) public onlyCompany
{
    require(applicants[_applicant].registered, "Applicant not registered");
    require(applicants[_applicant].verified, "Applicant not verified");


    // Add the company to the certificate's allowed companies list
    verifiedCertificates[_applicant][_certificateHash].allowedCompanies.push(msg.sender);


    // Notify the applicant that a company has requested access
    emit CompanyRequestedAccess(_applicant, msg.sender);
}


// Function for applicant to revoke access to a company
function revokeCompanyAccess(address _company) public onlyApplicant
{
    require(applicants[msg.sender].registered, "Applicant not registered");
    require(applicants[msg.sender].verified, "Applicant not verified");


    // Remove the company from the allowed companies list
    for (uint i = 0; i < applicants[msg.sender].allowedCompanies.length; i++)
    {
        if (applicants[msg.sender].allowedCompanies[i] == _company)
         {
            delete applicants[msg.sender].allowedCompanies[i];
            break;
        }
    }
}


// Function for company to view a verified certificate
function viewCertificate(address _applicant, bytes32 _certificateHash) public view onlyCompany returns (bytes32)
{
    require(applicants[_applicant].registered, "Applicant not registered");
    require(applicants[_applicant].verified, "Applicant not verified");


    // Check if the company is allowed to view the certificate
    bool allowed = false;
    for (uint i = 0; i < verifiedCertificates[_applicant][_certificateHash].allowedCompanies.length; i++)
    {
        if (verifiedCertificates[_applicant][_certificateHash].allowedCompanies[i] == msg.sender) {
            allowed = true;
            break;
        }
    }
    require(allowed, "Company not allowed to view certificate");


    // Return the IPFS hash of the certificate
    return verifiedCertificates[_applicant][_certificateHash].hash;
}
}

