// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/spdx.c
 *
 * SPDX output handling
 *
 * Copyright (C) 2018-2020 SCANOSS.COM
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

void spdx_open()
{
    printf("{\n");
    printf("  \"Document\": {\n");
    printf("    \"specVersion\": \"SPDX-2.0\",\n");
    printf("    \"creationInfo\": {\n");
    printf("      \"creators\": [\n");
    printf("        \"Tool: SCANOSS Inventory Engine\",\n");
    printf("        \"Organization: http://scanoss.com\"\n");
    printf("      ],\n");
    printf("      \"comment\": \"This SPDX report has been automatically generated\",\n");
    printf("      \"licenseListVersion\": \"1.19\",\n");

		printf("      \"created\": \"");
    print_datestamp();
		printf("\"\n");

    printf("    },\n");
    printf("    \"spdxVersion\": \"SPDX-2.0\",\n");
    printf("    \"dataLicense\": \"CC0-1.0\",\n");
    printf("    \"id\": \"SPDXRef-DOCUMENT\",\n");
    printf("    \"name\": \"SPDX-Tools-v2.0\",\n");
    printf("    \"comment\": \"This document was automatically generated with SCANOSS.\",\n");
    printf("    \"externalDocumentRefs\": [],\n");
    printf("    \"Packages\": [\n");
}

void spdx_xml_open(scan_data *scan)
{
    printf("<rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"\n");
    printf("    xmlns:spdx=\"http://spdx.org/rdf/terms#\"\n");
    printf("    xmlns:rdfs=\"http://www.w3.org/2000/01/rdf-schema#\">\n");
    printf("<spdx:SpdxDocument rdf:about=\"https://osskb.org/docs/spdx.rdf#SPDXRef-DOCUMENT\">\n");
    printf("  <spdx:specVersion>SPDX-2.1</spdx:specVersion>\n");
    printf("  <spdx:dataLicense rdf:resource=\"http://spdx.org/licenses/CC0-1.0\" />\n");
    printf("  <spdx:creationInfo>\n");
    printf("    <spdx:CreationInfo>\n");
    printf("      <spdx:licenseListVersion>2.6</spdx:licenseListVersion>\n");
    printf("      <spdx:creator>Person: OSSKB</spdx:creator>\n");
    printf("      <spdx:creator>Organization: SCANOSS</spdx:creator>\n");
    printf("      <spdx:creator>Tool: OSSKB</spdx:creator>\n");
    printf("      <spdx:created>");
    print_datestamp();
		printf("</spdx:created>\n");
    printf("    </spdx:CreationInfo>\n");
    printf("  </spdx:creationInfo>\n");
    printf("  <spdx:name>%s</spdx:name>\n", scan->file_path);
    printf("  <rdfs:comment>\n");
    printf("    This document was created by the SCANOSS engine by scanning against the OSSKB.ORG\n");
    printf("  </rdfs:comment>\n");
    printf("  <spdx:relationship>\n");
    printf("    <spdx:Relationship>\n");
    printf("      <spdx:relationshipType rdf:resource=\"http://spdx.org/rdf/terms#relationshipType_describes\" />\n");
    printf("      <spdx:relatedSpdxElement>\n");
    printf("        <spdx:Package rdf:about=\"https://osskb.org\">\n");
    printf("          <spdx:name>%s</spdx:name>\n", scan->file_path);
    printf("          <spdx:packageFileName>%s</spdx:packageFileName>\n", scan->file_path);
    printf("          <spdx:downloadLocation rdf:resource=\"http://spdx.org/rdf/terms#noassertion\" />\n");
    printf("          <spdx:packageVerificationCode>\n");
    printf("            <spdx:PackageVerificationCode>\n");
    printf("            <spdx:packageVerificationCodeValue>%s</spdx:packageVerificationCodeValue>\n", scan->source_md5);
    printf("            </spdx:PackageVerificationCode>\n");
    printf("          </spdx:packageVerificationCode>\n");
    printf("          <spdx:checksum>\n");
    printf("            <spdx:Checksum>\n");
    printf("              <spdx:algorithm rdf:resource=\"http://spdx.org/rdf/terms#checksumAlgorithm_md5\" />\n");
    printf("              <spdx:checksumValue>%s</spdx:checksumValue>\n", scan->source_md5);
    printf("            </spdx:Checksum>\n");
    printf("          </spdx:checksum>\n");
    printf("          <spdx:licenseConcluded>\n");
    printf("            <spdx:DisjunctiveLicenseSet>\n");
    printf("            </spdx:DisjunctiveLicenseSet>\n");
    printf("          </spdx:licenseConcluded>\n");
    printf("          <spdx:licenseConcluded rdf:resource=\"http://spdx.org/rdf/terms#noassertion\" />\n");
    printf("          <spdx:licenseDeclared rdf:resource=\"http://spdx.org/rdf/terms#noassertion\" />\n");
    printf("          <spdx:licenseInfoFromFiles rdf:resource=\"http://spdx.org/rdf/terms#noassertion\" />\n");
    printf("          <spdx:copyrightText rdf:resource=\"http://spdx.org/rdf/terms#noassertion\" />\n");
}

void spdx_close()
{
    printf("       ]\n");
    printf("      }\n");
    printf("}\n");
}

void spdx_xml_close()
{
    printf("        </spdx:Package>\n");
    printf("      </spdx:relatedSpdxElement>\n");
    printf("    </spdx:Relationship>\n");
    printf("  </spdx:relationship>\n");
    printf("</spdx:SpdxDocument>\n");
    printf("</rdf:RDF>\n");
}

void print_json_match_spdx(scan_data scan, match_data match)
{
    printf("         {\n");
    printf("          \"name\": \"%s\",\n", match.component);

    if (strcmp(match.version, match.latest_version))
    {
        printf("          \"versionInfo\": \"%s-%s\",\n", match.version, match.latest_version);
    }
    else
    {
        printf("          \"versionInfo\": \"%s\",\n", match.version);
    }

    printf("          \"supplier\": \"%s\",\n", match.vendor);
    char copyright[MAX_COPYRIGHT];
    get_copyright(match, copyright);
    printf("          \"copyrightText\": \"%s\",\n", copyright);
    printf("          \"downloadLocation\": \"%s\",\n", match.url);
    printf("          \"checksum\": [\n");
    printf("            {\n");
    printf("              \"algorithm\": \"checksumAlgorithm_md5\",\n");

    char *md5 = md5_hex(scan.md5);
    printf("              \"value\": \"%s\"\n", md5);
    free(md5);

    printf("            }\n");
    printf("          ],\n");
    printf("          \"description\": \"Detected by SCANOSS Inventorying Engine.\",\n");
    printf("          \"licenseConcluded\": \"\",\n");
		char license[MAX_LICENSE] = "\0";
    get_license(match, license);
    printf("          \"licenseInfoFromFiles\": \"%s\"\n", license);
 
    printf("         }\n");

    fflush(stdout);
}

void print_xml_match_spdx(scan_data scan, match_data match)
{
	char *md5 = md5_hex(match.file_md5);
	printf("          <spdx:hasFile>\n");
	printf("            <spdx:File rdf:about=\"https://osskb.org/api/file_contents/%s\">\n", md5);
	printf("              <spdx:fileName>%s</spdx:fileName>\n", match.file);
	printf("              <spdx:checksum>\n");
	printf("                <spdx:Checksum>\n");
	printf("                  <spdx:algorithm rdf:resource=\"http://spdx.org/rdf/terms#checksumAlgorithm_md5\" />\n");
	printf("                  <spdx:checksumValue>%s</spdx:checksumValue>\n", md5);
	printf("                </spdx:Checksum>\n");
	printf("              </spdx:checksum>\n");
	printf("              <spdx:licenseConcluded rdf:resource=\"http://spdx.org/rdf/terms#noassertion\" />\n");

	/* Print license */
	char license[MAX_LICENSE] = "\0";
	get_license(match, license);
	if (*license)
	printf("              <spdx:licenseInfoInFile rdf:resource=\"http://spdx.org/licenses/%s\" />\n", license);

	/* Print copyright */
	char copyright[MAX_COPYRIGHT] = "\0";
	get_copyright(match, copyright);
	if (*copyright)
	{
		printf("              <spdx:copyrightText><![CDATA[\n");
		printf("%s\n", copyright);
		printf("              ]]></spdx:copyrightText>\n");
	}

	printf("            </spdx:File>\n");
	printf("          </spdx:hasFile>\n");
	free(md5);

	fflush(stdout);
}
