//
//  CertificateToolApp.m
//  CertificateTool
//
//  Copyright (c) 2012-2015,2024 Apple Inc. All Rights Reserved.
//

#import "CertificateToolApp.h"
#import "DataConversion.h"
#import "PSCerts.h"
#import "PSUtilities.h"
#import "PSAssetConstants.h"
#import "PSCertData.h"
#import "PSCert.h"
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>


@interface CertificateToolApp (PrivateMethods)

- (void)usage;
- (NSString*)checkPath:(NSString*)name basePath:(NSString *)basePath isDirectory:(BOOL)isDirectory;

- (BOOL)buildEVRootsData:(NSDictionary *)certs;
- (BOOL)ensureDirectoryPath:(NSString *)dir_path;
- (BOOL)buildConstraintsTable;
- (BOOL)buildAnchorTable:(NSArray*)certs withConstraints:(NSDictionary*) constraints;
- (BOOL)outputAnchors:(NSArray *)certs;

@end

@implementation CertificateToolApp


@synthesize app_name = _app_name;
@synthesize root_directory = _root_directory;
@synthesize custom_directory = _custom_directory;
@synthesize platform_directory = _platform_directory;
@synthesize revoked_directory = _revoked_directory;
@synthesize distrusted_directory = _distrusted_directory;
@synthesize allowlist_directory = _allowlist_directory;
@synthesize certs_directory = _certs_directory;
@synthesize constraints_config_path = _constraints_config_path;
@synthesize evroot_config_path = _evroot_config_path;
@synthesize ev_plist_path = _ev_plist_path;
@synthesize info_plist_path = _info_plist_path;
@synthesize top_level_directory = _top_level_directory;
@synthesize output_directory = _output_directory;
@synthesize version_number_plist_path = _version_number_plist_path;
@synthesize version_number = _version_number;


- (id)init:(int)argc withArguments:(const char**)argv
{
    if ((self = [super init]))
    {
		_app_name = [[NSString alloc] initWithUTF8String:argv[0]];

        // set all of the directory paths to nil
		_root_directory = nil;
        _custom_directory = nil;
        _platform_directory = nil;
		_revoked_directory = nil;
		_distrusted_directory = nil;
		_allowlist_directory = nil;
		_certs_directory = nil;
        _constraints_config_path = nil;
        _evroot_config_path = nil;
		_ev_plist_path = nil;
        _info_plist_path = nil;
		_top_level_directory = nil;
        _output_directory = nil;
        _version_number_plist_path = nil;
        _version_number = nil;


		_certRootsData = nil;
		_blocked_keys = nil;
        _gray_listed_keys = nil;

        _allow_list_data = [NSMutableDictionary dictionary];
        _EVRootsData = [NSMutableDictionary dictionary];
		_derData = nil;


        // Parse the command line arguments and set up the directory paths
        for (int iCnt = 1; iCnt < argc; iCnt++)
        {
            const char* arg = argv[iCnt];
            if (!strcmp(arg, "-h") || !strcmp(arg, "--help"))
            {
                [self usage];
                return nil;
            }
            else if (!strcmp(arg, "-r") || !strcmp(arg, "--roots_dir"))
            {
                if ((iCnt + 1) == argc)
                {
                    [self usage];
                    return nil;
                }

                _root_directory = [[NSString stringWithUTF8String:argv[iCnt + 1]] stringByExpandingTildeInPath];
                iCnt++;

            }
			else if (!strcmp(arg, "-k") || !strcmp(arg, "--revoked_dir"))
            {
                if ((iCnt + 1) == argc)
                {
                    [self usage];
                    return nil;
                }

                _revoked_directory = [[NSString stringWithUTF8String:argv[iCnt + 1]]  stringByExpandingTildeInPath];
                iCnt++;
            }
			else if (!strcmp(arg, "-d") || !strcmp(arg, "--distrusted_dir"))
            {
                if ((iCnt + 1) == argc)
                {
                    [self usage];
                    return nil;
                }

                _distrusted_directory = [[NSString stringWithUTF8String:argv[iCnt + 1]] stringByExpandingTildeInPath];
                iCnt++;
            }
            else if (!strcmp(arg, "-a") || !strcmp(arg, "--allowlist_dir"))
            {
                if ((iCnt + 1) == argc)
                {
                    [self usage];
                    return nil;
                }

                _allowlist_directory = [[NSString stringWithUTF8String:argv[iCnt + 1]] stringByExpandingTildeInPath];
                iCnt++;
            }
			else if (!strcmp(arg, "-c") || !strcmp(arg, "--certs_dir"))
            {
                if ((iCnt + 1) == argc)
                {
                    [self usage];
                    return nil;
                }

                _certs_directory = [[NSString stringWithUTF8String:argv[iCnt + 1]] stringByExpandingTildeInPath];
                iCnt++;
            }
			else if (!strcmp(arg, "-e") || !strcmp(arg, "--evroot.config"))
            {
                if ((iCnt + 1) == argc)
                {
                    [self usage];
                    return nil;
                }

                _evroot_config_path = [[NSString stringWithUTF8String:argv[iCnt + 1]] stringByExpandingTildeInPath];
                iCnt++;
            }

            else if (!strcmp(arg, "-i") || !strcmp(arg, "--info_plist_path"))
            {
                if ((iCnt + 1) == argc)
                {
                    [self usage];
                    return nil;
                }

                _info_plist_path = [[NSString stringWithUTF8String:argv[iCnt + 1]] stringByExpandingTildeInPath];
                iCnt++;
            }
			else if (!strcmp(arg, "-t") || !strcmp(arg, "--top_level_directory"))
            {
                if ((iCnt + 1) == argc)
                {
                    [self usage];
                    return nil;
                }

                _top_level_directory = [[NSString stringWithUTF8String:argv[iCnt + 1]] stringByExpandingTildeInPath];
                iCnt++;
            }
            else if (!strcmp(arg, "-o") || !strcmp(arg, "--output_directory"))
            {
                if ((iCnt + 1) == argc)
                {
                    [self usage];
                    return nil;
                }

                _output_directory = [[NSString stringWithUTF8String:argv[iCnt + 1]] stringByExpandingTildeInPath];
                iCnt++;
            }
            else if (!strcmp(arg, "-v") || !strcmp(arg, "--version_number"))
            {
                if ((iCnt + 1) == argc)
                {
                    [self usage];
                    return nil;
                }

                NSString* temp_number_str = [NSString stringWithUTF8String:argv[iCnt + 1]];
                if (nil != temp_number_str)
                {
                    NSInteger value = [temp_number_str integerValue];
                    if (value > 0)
                    {
                        _version_number = [NSNumber numberWithInteger:value];
                    }
                }
            }
        }

        if (nil == _root_directory)
        {
			_root_directory = [self checkPath:@"certificates/roots" basePath:_top_level_directory isDirectory:YES];
		 	if (nil == _root_directory)
			{
				[self usage];
				return nil;
        	}
		}

        if (nil == _custom_directory)
        {
            _custom_directory = [self checkPath:@"certificates/custom" basePath:_top_level_directory isDirectory:YES];
            if (nil == _custom_directory)
            {
                [self usage];
                return nil;
            }
        }

        if (nil == _platform_directory)
        {
            _platform_directory = [self checkPath:@"certificates/platform" basePath:_top_level_directory isDirectory:YES];
            if (nil == _platform_directory)
            {
                [self usage];
                return nil;
            }
        }

		if (nil == _revoked_directory)
		{
			_revoked_directory = [self checkPath:@"certificates/revoked" basePath:_top_level_directory isDirectory:YES];
		 	if (nil == _revoked_directory)
			{
				[self usage];
				return nil;
        	}
		}

		if (nil == _distrusted_directory)
		{
			_distrusted_directory = [self checkPath:@"certificates/distrusted" basePath:_top_level_directory isDirectory:YES];
		 	if (nil == _distrusted_directory)
			{
				// distrusted list is no longer required: rdar://92699800
        	}
		}

		if (nil == _allowlist_directory)
		{
			_allowlist_directory = [self checkPath:@"certificates/allowlist" basePath:_top_level_directory isDirectory:YES];
			if (nil == _allowlist_directory)
			{
				// allowlist is no longer required: rdar://29338872
			}
		}
		if (nil == _certs_directory)
		{
			_certs_directory = [self checkPath:@"certificates/removed/intermediates" basePath:_top_level_directory isDirectory:YES];
		 	if (nil == _certs_directory)
			{
				[self usage];
				return nil;
        	}
		}

        if (nil == _constraints_config_path)
        {
            _constraints_config_path = [self checkPath:@"certificates/constraints.json" basePath:_top_level_directory isDirectory:NO];
             if (nil == _constraints_config_path)
            {
                [self usage];
                return nil;
            }
        }

		if (nil == _evroot_config_path)
		{
			_evroot_config_path = [self checkPath:@"certificates/evroot.config" basePath:_top_level_directory isDirectory:NO];
		 	if (nil == _evroot_config_path)
			{
				[self usage];
				return nil;
        	}
		}

        if (nil == _info_plist_path)
        {
            _info_plist_path =  [self checkPath:@"config/Info-Asset.plist" basePath:_top_level_directory isDirectory:NO];
            if (nil == _info_plist_path)
			{
				[self usage];
				return nil;
        	}
        }
        if (nil == _version_number_plist_path)
        {
            _version_number_plist_path = [self checkPath:@"config/AssetVersion.plist" basePath:_top_level_directory isDirectory:NO];
            if (nil == _info_plist_path)
            {
                [self usage];
				return nil;
            }
        }
    }
    return self;
}

- (void)usage
{
	printf("%s usage:\n", [self.app_name UTF8String]);
	printf(" [-h, --help]          			\tPrint out this help message\n");
	printf(" [-r, --roots_dir]     			\tThe full path to the directory with the certificate roots\n");
	printf(" [-k, --revoked_dir]   			\tThe full path to the directory with the revoked certificates\n");
	printf(" [-d, --distrusted_dir] 		\tThe full path to the directory with the distrusted certificates\n");
	printf(" [-a, --allowlist_dir]          \tThe full path to the directory with the allowlist certificates\n");
	printf(" [-c, --certs_dir] 				\tThe full path to the directory with the cert certificates\n");
	printf(" [-e, --evroot.config] 			\tThe full path to the evroot.config file\n");
    printf(" [-i, --info_plist_path])       \tThe full path to the Info.plist file\n");
	printf(" [-t, --top_level_directory]	\tThe full path to the top level security_certificates directory\n");
	printf(" [-o, --output_directory]       \tThe full path to the directory to write out the results\n");
    printf(" [-v, --version_number]         \tThe version number of the asset\n");
	printf("\n");
}

- (NSString*)checkPath:(NSString*)name basePath:(NSString *)basePath isDirectory:(BOOL)isDirectory
{
	NSString* result = nil;
	if (nil == name)
	{
		return result;
	}

	NSFileManager* fileManager = [NSFileManager defaultManager];
	BOOL isDir = NO;

	if ([name hasPrefix:@"/"] || [name hasPrefix:@"~"])
	{
        name = [name hasPrefix:@"~"] ? [name stringByExpandingTildeInPath] : name;
		// This is a full path
		if (![fileManager fileExistsAtPath:name isDirectory:&isDir] || isDir != isDirectory)
		{
			NSLog(@"%@ is invalid", name);
			return result;
		}
		result = name;
	}
	else
	{
		NSString* full_path = nil;
		if (nil == basePath)
		{
			NSLog(@"%@ is not a full path but basePath is nil", name);
			return result;
		}

		full_path = [basePath stringByAppendingPathComponent:name];
		if (![fileManager fileExistsAtPath:full_path isDirectory:&isDir] || isDir != isDirectory)
		{
			NSLog(@"%@ is invalid", full_path);
			return result;
		}
		result = full_path;
	}
	return result;
}

/* --------------------------------------------------------------------------
    Read in the evroot.config file and create a dictionary on the cert file
    names and relate then to their EVRoot OIDs
   -------------------------------------------------------------------------- */
- (BOOL)buildEVRootsData:(NSDictionary *)certs
{
    BOOL result = NO;

    if (nil == _EVRootsData || nil == _evroot_config_path)
    {
        return result;
    }

    // Read file into memory it is not that big
    NSError* error = nil;
    NSData* fileData = [NSData dataWithContentsOfFile:self.evroot_config_path
                           options:NSDataReadingMappedIfSafe error:&error];
    if (nil == fileData)
    {
        return result;
    }

    // Turn the data into a string so that it can be edited
    NSMutableString* evconfig_data = [[NSMutableString alloc] initWithData:fileData
                                        encoding:NSUTF8StringEncoding];
    if (nil == evconfig_data)
    {
        return result;
    }

    // Use Regex to remove all of the comments
    NSRegularExpression* regex_comments =
        [NSRegularExpression regularExpressionWithPattern:@"^#.*\n"
                options:NSRegularExpressionAnchorsMatchLines error:&error];

    NSRange full_string_range = NSMakeRange(0, [evconfig_data length]);
    NSUInteger num_replacements =
        [regex_comments replaceMatchesInString:evconfig_data
                options:0 range:full_string_range withTemplate:@""];

    if (0 == num_replacements)
    {
        return result;
    }

    // Use Regex to remove all of the blank lines
    NSRegularExpression* regex_blankLines =
        [NSRegularExpression regularExpressionWithPattern:@"^\n"
            options:NSRegularExpressionAnchorsMatchLines error:&error];

    full_string_range = NSMakeRange(0, [evconfig_data length]);
    num_replacements = [regex_blankLines replaceMatchesInString:evconfig_data
                            options:0 range:full_string_range withTemplate:@""];

    if (0 == num_replacements)
    {
        return result;
    }

    // Break the single string into an array of lines.
    NSArray* strings = [evconfig_data componentsSeparatedByString:@"\n"];
    if (nil == strings)
    {
        return result;
    }

    // Process each line in the array
    for (NSString* aLine in strings)
    {
        if (nil == aLine || [aLine length] < 2)
        {
            continue;
        }
        NSRegularExpression* regex_oid_str = [NSRegularExpression regularExpressionWithPattern:@"^[[0-9]+.]+"
			options:NSRegularExpressionAnchorsMatchLines error:&error];

		full_string_range = NSMakeRange(0, [aLine length]);
		NSArray* oid_str_matchs = [regex_oid_str matchesInString:aLine options:0 range:full_string_range];
		NSTextCheckingResult* ck_result = [oid_str_matchs objectAtIndex:0];
		NSRange result_range = [ck_result rangeAtIndex:0];
		NSString* oid_str = [aLine substringToIndex:result_range.length];
		NSString* remainder_str = [aLine substringFromIndex:(result_range.length + 1)];
		NSArray* items = [remainder_str componentsSeparatedByString:@"\""];

        // The first item should be an OID string
        NSUInteger num_items = [items count];
        //NSString* oid_str = [items objectAtIndex:0];
        NSUInteger iCnt = 0;

		NSMutableSet* cert_digests = [NSMutableSet set];
        // loop through the names of all of the cert files
        for (iCnt = 1; iCnt < num_items; iCnt++)
        {
            NSString* cert_file_name = [items objectAtIndex:iCnt];
			if (cert_file_name == nil || [cert_file_name hasPrefix:@" "] || [cert_file_name length] < 2)
			{
				continue;
			}
			//NSLog(@"cert_file_name = %@", cert_file_name);

			// find the PSCert record for the file
			PSCert* aCert = [certs objectForKey:cert_file_name];
			if (nil != aCert)
			{
				[cert_digests addObject:aCert.certificate_hash];
			}
			else
			{
				NSLog(@"buildEVRootsData: could not find the cert for %@", cert_file_name);
			}
		}

        // Add certificates for current vendor-specific OID
        NSMutableArray* existing_certs = [_EVRootsData objectForKey:oid_str];
        if (nil != existing_certs)
        {
            [cert_digests addObjectsFromArray:existing_certs];
        }

		[_EVRootsData setObject:[cert_digests allObjects] forKey:oid_str];

        // Add (all) certificates for generic CAB Forum OID
        existing_certs = [_EVRootsData objectForKey:@"2.23.140.1.1"];
        if ( nil != existing_certs)
        {
            [cert_digests addObjectsFromArray:existing_certs];
        }

        [_EVRootsData setObject:[cert_digests allObjects] forKey:@"2.23.140.1.1"];
    }

    result = YES;
    return result;
}

/* --------------------------------------------------------------------------
 * Assemble allowlist from issuer certificates and associated allowed leaves.
 * Leaves are stored in a directory named with the subj key ID of the issuer.
 * The resulting plist is a dictionary:
 *	key: subj key ID of the issuing CA
 *	value: array of SHA-256 hashes of leaf certificates
 -------------------------------------------------------------------------- */
- (BOOL)buildAllowListData
{
	BOOL result = NO;

	PSAssetFlags certFlags = isAnchor | isAllowListed;
	NSNumber *issuersFlags = [NSNumber numberWithUnsignedLong:certFlags];
	NSString *issuersDir =[self.allowlist_directory stringByAppendingPathComponent: @"issuers"];

	PSCerts* pscerts_alissuers = [[PSCerts alloc] initWithCertFilePath:issuersDir withFlags:issuersFlags recurse:NO];
	if (nil == pscerts_alissuers || nil == pscerts_alissuers.certs)
	{
		return YES; // this is no longer an error, since issuers may be empty: rdar://29338872
	}

	certFlags = isAllowListed;
	NSNumber *leafFlags = [NSNumber numberWithUnsignedLong:certFlags];
	for (PSCert *alIssuer in pscerts_alissuers.certs)
	{
		// find leaf certificates in directory named with this issuer's subject key ID
		if (nil == alIssuer.subj_key_id)
		{
			return result;
		}

		NSString *leaf_dir_path = [self.allowlist_directory stringByAppendingPathComponent:alIssuer.subj_key_id];
		PSCerts *leaf_certs = [[PSCerts alloc] initWithCertFilePath:leaf_dir_path withFlags:leafFlags recurse:NO];

		// set allowlist dictionary entry: <issuer subj key id>:<issued leaf hashes>
		NSMutableArray *leaf_hashes = [NSMutableArray array];
		for (PSCert *leaf in leaf_certs.certs)
		{
			[leaf_hashes addObject: leaf.certificate_sha256_hash];
		}

		[leaf_hashes sortUsingComparator: ^(id obj1, id obj2) {
			NSData *d1 = (NSData *)obj1;
			NSData *d2 = (NSData *)obj2;
			int greaterThan = 0;

			if ([d1 length] == [d2 length]) {
				greaterThan = memcmp([d1 bytes], [d2 bytes], [d1 length]);
			} else {
				// shouldn't happen as hashes are all the same length
				NSUInteger length = ([d1 length] > [d2 length]) ? [d2 length] : [d1 length];
				greaterThan = memcmp([d1 bytes], [d2 bytes], length);
				if (!greaterThan) {
					greaterThan = [d1 length] > [d2 length];
				}
			}

			if (greaterThan > 0) {
				return (NSComparisonResult)NSOrderedDescending;
			} else if (greaterThan < 0) {
				return (NSComparisonResult)NSOrderedAscending;
			} else {
				return (NSComparisonResult)NSOrderedSame;
			}
		}];
		[_allow_list_data setValue:leaf_hashes forKey:alIssuer.subj_key_id];
	}

	result = YES;
	return result;
}

- (BOOL)ensureDirectoryPath:(NSString *)dir_path
{
    BOOL result = NO;

    if (nil == dir_path)
    {
        return result;
    }

    NSFileManager* fileManager = [NSFileManager defaultManager];
    NSError* error = nil;
    BOOL isDir = NO;

    if (![fileManager fileExistsAtPath:dir_path isDirectory:&isDir])
    {
        result = [fileManager createDirectoryAtPath:dir_path withIntermediateDirectories:YES attributes:nil error:&error];
        if (nil != error)
        {
            result = NO;
        }

    }
    else if (isDir)
    {
        result = YES;
    }

    return result;
}

- (NSMutableArray*)anchorCertificates
{
    // return array of PSCert for all system roots, platform roots, and custom anchors
    PSAssetFlags certFlags = isAnchor | hasFullCert | isSystem;
    PSCerts* pscerts_roots = [[PSCerts alloc] initWithCertFilePath:self.root_directory withFlags:[NSNumber numberWithUnsignedLong:certFlags]];
    certFlags = isAnchor | hasFullCert | isPlatform;
    PSCerts* pscerts_platform = [[PSCerts alloc] initWithCertFilePath:self.platform_directory withFlags:[NSNumber numberWithUnsignedLong:certFlags]];
    certFlags = isAnchor | hasFullCert | isCustom;
    PSCerts* pscerts_custom = [[PSCerts alloc] initWithCertFilePath:self.custom_directory withFlags:[NSNumber numberWithUnsignedLong:certFlags]];
    NSMutableArray* certs = [NSMutableArray array];
    [certs addObjectsFromArray:pscerts_roots.certs];
    [certs addObjectsFromArray:pscerts_platform.certs];
    [certs addObjectsFromArray:pscerts_custom.certs];
    return certs;
}

- (BOOL)processCertificates
{
	BOOL result = NO;

    // From the roots directory, create the index and table data for the asset
    PSAssetFlags certFlags = isAnchor | hasFullCert | isSystem;
    NSNumber* flags = [NSNumber numberWithUnsignedLong:certFlags];
    PSCerts* pscerts_roots = [[PSCerts alloc] initWithCertFilePath:self.root_directory withFlags:flags];
	_certRootsData = [[PSCertData alloc] initWithCertificates:pscerts_roots.certs];

    // Create constraints table from configuration file
    if (![self buildConstraintsTable]) {
        NSLog(@"Error: unable to build constraints table");
        return NO;
    }

    // Create anchor table from certs and constraints
    NSMutableArray* certs = [self anchorCertificates];
    if (![self buildAnchorTable:certs withConstraints:_constraints_table]) {
        NSLog(@"Error: unable to build anchor table");
        return NO;
    }

    // Copy anchor certs to the output Anchors directory
    if (![self outputAnchors:certs]) {
        NSLog(@"Error: unable to copy anchors to output directory");
        return NO;
    }

    // From the blocked and gray listed certs create an array of the keys.
	NSMutableArray* gray_certs = [NSMutableArray array];
    certFlags = isGrayListed | hasFullCert;
    flags = [NSNumber numberWithUnsignedLong:certFlags];
    PSCerts* pscerts_gray = [[PSCerts alloc] initWithCertFilePath:self.distrusted_directory withFlags:flags];
    [gray_certs addObjectsFromArray:pscerts_gray.certs];

	_gray_listed_keys = [NSMutableArray array];
	for (PSCert* aCert in gray_certs)
	{
		NSData *pkh = aCert.public_key_hash;
		if (pkh && ![_gray_listed_keys containsObject:pkh]) {
			[_gray_listed_keys addObject:pkh];
		}
	}

    NSMutableArray* blocked_certs = [NSMutableArray array];
    certFlags = isBlocked | hasFullCert;
    flags = [NSNumber numberWithUnsignedLong:certFlags];
    PSCerts* pscerts_blocked = [[PSCerts alloc] initWithCertFilePath:self.revoked_directory withFlags:flags];
    [blocked_certs addObjectsFromArray:pscerts_blocked.certs];

	_blocked_keys = [NSMutableArray array];
	for (PSCert* aCert in blocked_certs)
	{
		NSData *pkh = aCert.public_key_hash;
		if (pkh && ![_blocked_keys containsObject:pkh]) {
			[_blocked_keys addObject:pkh];
		}
	}

/*
    On iOS the intermediate certs are not used
    certFlags = hasFullCert;
    flags = [NSNumber numberWithUnsignedLong:certFlags];
    pscerts = [[PSCerts alloc] initWithCertFilePath:self.certs_directory withFlags:flags];
    [certs addObjectsFromArray:pscerts.certs];
*/
    // now create the evroots.plist data
    NSMutableDictionary* file_name_to_cert = [NSMutableDictionary dictionary];

    for (PSCert* aCert in pscerts_roots.certs)
    {
        NSString* just_file_name = [aCert.file_path lastPathComponent];
        [file_name_to_cert setObject:aCert forKey:just_file_name];
    }

	if (![self buildEVRootsData:file_name_to_cert])
	{
		NSLog(@"Unable to create the EVPlist data");
		return result;
	}

	if (![self buildAllowListData])
	{
		NSLog(@"Unable to create the allow list plist data");
		return result;
	}

    result = YES;
    return result;
}

- (BOOL)buildConstraintsTable
{
    if (!_constraints_config_path) { return NO; }
    NSDictionary* constraints = nil;

    // Read config file into memory
    NSError* error = nil;
    NSData* fileData = [NSData dataWithContentsOfFile:self.constraints_config_path
                           options:NSDataReadingMappedIfSafe error:&error];
    if (!fileData) { return NO; }
    constraints = [NSJSONSerialization JSONObjectWithData:fileData options:0 error:&error];
    if (!constraints) { return NO; }
    _constraints_table = constraints;
    return YES;
}

- (BOOL)buildAnchorTable:(NSArray*)certs withConstraints:(NSDictionary*) constraints
{
    if (!certs) { return NO; }
    // Create dictionary keyed by normalized subject hash
    NSMutableDictionary* records = [NSMutableDictionary dictionary];
    for (PSCert* aCert in certs) {
        // Get the hash
        NSData* normalized_subject_hash = aCert.normalized_subject_hash;
        if (!normalized_subject_hash) {
            NSLog(@"Could not get the normalized hash for the cert at %@", aCert.file_path);
            return NO;
        }
        // See if there is already an entry with this value (multiple certs may have same subject hash)
        NSString *normalized_subject_hash_str = [[normalized_subject_hash toHexString] uppercaseString];
        NSMutableArray* items = [records objectForKey:normalized_subject_hash_str];
        if (!items) {
            // new item
            items = [NSMutableArray array];
        }
        // Create a lookup dictionary for each anchor cert with these keys:
        // "sha2" = (certificate digest as hex string)
        // "spki-sha2" = (spki digest as hex string)
        // "oids" = (array of permitted policy oids as string, if present)
        // "type" = (string: "none", "system", "platform", "custom")
        NSMutableDictionary* anchor = [NSMutableDictionary dictionary];
        NSString* cert_hash_str = [[aCert.certificate_sha256_hash toHexString] uppercaseString];
        [anchor setObject:cert_hash_str forKey:@"sha2"];
        NSString* spki_hash_str = [[aCert.spki_hash toHexString] uppercaseString];
        [anchor setObject:spki_hash_str forKey:@"spki-sha2"];
        NSArray* policy_oids = [constraints objectForKey:cert_hash_str];
        if (!policy_oids) { policy_oids = [NSArray array]; }
        [anchor setObject:policy_oids forKey:@"oids"];
        [anchor setObject:aCert.anchor_type forKey:@"type"];

        PSAssetFlags assetFlags = [aCert.flags unsignedLongValue];
        if (assetFlags & (isAnchor | hasFullCert)) {
            // add only if we have the cert data and it is considered an anchor
            [items addObject:anchor];
            [records setObject:items forKey:normalized_subject_hash_str];
        }
    }
    _anchor_lookup_table = records;
    return YES;
}

- (BOOL)outputAnchors:(NSArray*)certs
{
    NSError* error = nil;
    NSString* anchors_path = nil;
    if (!certs) {
        NSLog(@"Error: no anchors provided to output");
        return NO;
    }
    anchors_path = [self.output_directory stringByAppendingPathComponent:@"Anchors"];
    if (![self ensureDirectoryPath:anchors_path]) {
        NSLog(@"Error: unable to ensure the output Anchors directory!");
        return NO;
    }
    for (PSCert* aCert in certs) {
        NSString* src_path = aCert.file_path;
        NSString* hash_name = [NSString stringWithFormat:@"%@.cer",
                               [[aCert.certificate_sha256_hash toHexString] uppercaseString]];
        NSString *dst_path = [anchors_path stringByAppendingPathComponent:hash_name];
        NSFileManager* fileManager = [NSFileManager defaultManager];
        if (![fileManager copyItemAtPath:src_path toPath:dst_path error:&error]) {
            NSLog(@"Error: unable to copy \"%@\" to \"%@\": %@", src_path, dst_path, error);
            return NO;
        }
    }
    return YES;
}

- (BOOL)outputPlistsToDirectory
{
    BOOL result = NO;
	NSError* error = nil;
	NSString* path_str = nil;

	if (nil != _EVRootsData && _EVRootsData.count > 0)
	{
        if (![self ensureDirectoryPath:self.output_directory])
        {
            NSLog(@"Error unable to ensure the output directory!");
			return result;
        }

		NSData* evroots_data = [NSPropertyListSerialization dataWithPropertyList:_EVRootsData
	                            format:NSPropertyListBinaryFormat_v1_0 /*NSPropertyListXMLFormat_v1_0*/ options:0
	                            error:&error];
		if (nil != error)
		{
			NSLog(@"Error converting out the evroot data into data: error %@", error);
			return result;
		}

		path_str = [self.output_directory stringByAppendingPathComponent:@"EVRoots.plist"];
		if (![evroots_data writeToFile:path_str options:0 error:&error])
		{
			NSLog(@"Error writing out the evroot.plist data: error %@", error);
			return result;
		}
	}

    if (nil != _gray_listed_keys && _gray_listed_keys.count > 0)
    {
        NSData* graylist_roots_data = [NSPropertyListSerialization dataWithPropertyList:_gray_listed_keys
                                                                                  format:NSPropertyListBinaryFormat_v1_0 /*NSPropertyListXMLFormat_v1_0*/ options:0
                                                                                   error:&error];
		if (nil != error)
		{
			NSLog(@"Error converting the gray listed keys into data: error %@", error);
			return result;
		}

		path_str = [self.output_directory stringByAppendingPathComponent:@"GrayListedKeys.plist"];
		if (![graylist_roots_data writeToFile:path_str options:0 error:&error])
		{
			NSLog(@"Error writing out the GrayListedKeys.plist data: error %@", error);
			return result;
		}

    }

	if (nil != _blocked_keys && _blocked_keys.count > 0)
	{
		NSData* blocked_roots_data = [NSPropertyListSerialization dataWithPropertyList:_blocked_keys
	                            format:NSPropertyListBinaryFormat_v1_0 /*NSPropertyListXMLFormat_v1_0*/ options:0
	                            error:&error];
		if (nil != error)
		{
			NSLog(@"Error converting the blocked list into data: error %@", error);
			return result;
		}

		path_str = [self.output_directory stringByAppendingPathComponent:@"Blocked.plist"];
		if (![blocked_roots_data writeToFile:path_str options:0 error:&error])
		{
			NSLog(@"Error writing out the Blocked.plist data: error %@", error);
			return result;
		}
	}

	if (nil != _allow_list_data && _allow_list_data.count > 0)
	{
		NSData* allow_list_plist = [NSPropertyListSerialization dataWithPropertyList:_allow_list_data
			format:NSPropertyListBinaryFormat_v1_0 /*NSPropertyListXMLFormat_v1_0*/ options:0
			error:&error];
		if (nil != error)
		{
			NSLog(@"Error converting the allow list into data: error %@", error);
			return result;
		}

		path_str = [self.output_directory stringByAppendingPathComponent:@"Allowed.plist"];
		if (![allow_list_plist writeToFile:path_str options:0 error:&error])
		{
			NSLog(@"Error writing out the Allowed.plist data: error %@", error);
			return result;
		}
	}

	NSData* index_data = _certRootsData.cert_index_data;
	path_str = [self.output_directory stringByAppendingPathComponent:@"certsIndex.data"];
	if (nil != index_data)
	{
		if (![index_data writeToFile:path_str options:0 error:&error])
		{
			NSLog(@"Error writing out the certsIndex data: error %@", error);
			return result;
		}
	}

	NSData* cert_table_data = _certRootsData.cert_table;
	path_str = [self.output_directory stringByAppendingPathComponent:@"certsTable.data"];
    if (nil != cert_table_data)
	{
		if (![cert_table_data writeToFile:path_str options:0 error:&error])
		{
			NSLog(@"Error writing out the certsTable data: error %@", error);
			return result;
		}
	}

    path_str = [self.output_directory stringByAppendingPathComponent:@"Anchors.plist"];
    if (_anchor_lookup_table) {
        NSData* anchor_plist = [NSPropertyListSerialization dataWithPropertyList:_anchor_lookup_table
            format:NSPropertyListBinaryFormat_v1_0 /*NSPropertyListXMLFormat_v1_0*/ options:0
            error:&error];
        if (error) {
            NSLog(@"Error converting the anchor lookup table into plist data: error %@", error);
            return result;
        }
        if (![anchor_plist writeToFile:path_str options:0 error:&error])
        {
            NSLog(@"Error writing out Anchors.plist data: error %@", error);
            return result;
        }
    }

    path_str = [self.output_directory stringByAppendingPathComponent:@"AssetVersion.plist"];

    NSFileManager* fileManager = [NSFileManager defaultManager];
    // check to see if the file exists;
    if ([fileManager fileExistsAtPath:path_str])
    {
        if (![fileManager removeItemAtPath:path_str error:&error])
        {
            NSLog(@"Unable to remove the older version of the AssetVersion.plist file!");
            return result;
        }
    }

    if (![[NSFileManager defaultManager] copyItemAtPath:self.version_number_plist_path toPath:path_str error:&error])
    {
        NSLog(@"Error copying over the AssetVersion.plist file: error %@", error);
        return result;
    }

    return YES;
}

- (BOOL)createManifest
{
    BOOL result = NO;

    if (nil == self.version_number_plist_path)
    {
        return result;
    }


    unsigned char hash_buffer[CC_SHA256_DIGEST_LENGTH];

    NSString* evroots_str = @"EVRoots.plist";
    NSString* blocked_str = @"Blocked.plist";
    NSString* certsIndex_str = @"certsIndex.data";
    NSString* certsTable_str = @"certsTable.data";
    NSString* assetVersion_str = @"AssetVersion.plist";
    NSError* error = nil;

    NSInputStream* input_stream = [NSInputStream inputStreamWithFileAtPath:self.version_number_plist_path];
    [input_stream open];
    NSDictionary* version_number_dict = [NSPropertyListSerialization propertyListWithStream:input_stream options:0 format:nil error:&error];
    if (nil != error)
    {
        [input_stream close];
        NSLog(@"Error getting the version number info %@", error);
        return result;
    }
    [input_stream close];
    NSNumber* version_number = [version_number_dict objectForKey:@"VersionNumber"];


    NSArray* file_list = [NSArray arrayWithObjects:evroots_str, blocked_str, certsIndex_str, certsTable_str, assetVersion_str, nil];
    NSMutableDictionary* manifest_dict = [NSMutableDictionary dictionary];

    for (NSString* file_path in file_list)
    {
        NSString* full_path = [self.output_directory stringByAppendingPathComponent:file_path];
        NSData* hash_data = [NSData dataWithContentsOfFile:full_path options:0 error:&error];
        if (nil != error)
        {
            NSLog(@"Error getting the data for file %@", file_path);
            return result;
        }
        memset(hash_buffer, 0, CC_SHA256_DIGEST_LENGTH);
        CC_SHA256([hash_data bytes], (CC_LONG)[hash_data length] , hash_buffer);
        NSData* hash_value = [NSData dataWithBytes:hash_buffer length:CC_SHA256_DIGEST_LENGTH];
        [manifest_dict setObject:hash_value forKey:file_path];
    }

    // Add the version number to the manifest dictionary
    if (nil != version_number)
    {
        [manifest_dict setObject:version_number forKey:@"VersionNumber"];
    }

    NSData* manifest_property_list = [NSPropertyListSerialization dataWithPropertyList:manifest_dict format:NSPropertyListBinaryFormat_v1_0 options:0 error:&error];
    if (nil != error)
    {
        NSLog(@"Error converting the manifest_dict into a propertylist data object");
        return result;
    }


    NSString* path_str = [self.output_directory stringByAppendingPathComponent:@"manifest.data"];
    if (![manifest_property_list writeToFile:path_str options:0 error:&error])
    {
        NSLog(@"Error writing out the manifest data: error %@", error);
        return result;
    }
    result = YES;


    return result;
}


@end
