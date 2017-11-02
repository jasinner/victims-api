/*
* victi.ms API microservice
* Copyright (C) 2017 The victi.ms team
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Affero General Public License as published
* by the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package types

// CVE is a single CVE
type CVE string

// CVEs is a list of CVE instances
type CVEs []CVE

// Append appends a list of CVEs to the current CVEs instance
func (c *CVEs) Append(cves []CVE) {
	for _, cve := range cves {
		*c = append(*c, cve)
	}
}

func (c *CVEs) AppendSingle(cve string) {
	*c = append(*c, CVE(cve))
}


// Size returns the size of the internal list
func (c *CVEs) Size() int {
	return len(*c)
}
