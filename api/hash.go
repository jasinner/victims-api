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

package api

import (
	"io"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/victims/victims-api/db"
	"github.com/victims/victims-api/log"
	"github.com/victims/victims-api/types"
	"gopkg.in/mgo.v2/bson"
)

// SimpleSearch checks one against the victims databse looking for matches.
func SimpleSearch(c *gin.Context) {
	// Bind requestor input to SingleHashRequest
	requestedHash := types.SingleHashRequest{}
	c.BindJSON(&requestedHash)

	// Grab our collection and search for the hash
	col, _ := db.GetCollection("hashes")
	cursor := col.Find(bson.M{"hash": requestedHash.Hash})

	// If we have a result then store it ...
	count, _ := cursor.Count()
	log.Logger.Debug("Found %d hashes", count)
	if count == 1 {
		result := types.Hash{}
		cursor.One(&result)
		// and return the cves as JSON
		c.JSON(200, result.Cves)
		return
	}

	// Fall through to not found
	c.AbortWithStatus(404)
}

// deepSearch executes searching across all hash fields
func deepSearch(requestedHash types.MultipleHashRequest) types.CVEs {
	// Get the collection and set up some defaults for use later
	col, _ := db.GetCollection("hashes")
	count := 0
	cves := types.CVEs{}

	// For each requested hash
	for _, singleHash := range requestedHash.Hashes {
		log.Logger.Infof("Looking for %s\n\n", singleHash.Hash)
		results := []types.Hash{}
		// Search for hashes inside stored structures
		// TODO: Is this the best way?
		col.Find(
			bson.M{"$or": []interface{}{
				bson.M{"hash": singleHash.Hash},
				bson.M{"combinedhash": singleHash.Hash},
				bson.M{"filehashes": bson.M{"$elemMatch": bson.M{"hash": singleHash.Hash}}},
			},
			},
		).All(&results)
		// col.Find(
		// 	bson.M{
		// 		"filehashes": bson.M{
		// 			"$elemMatch": bson.M{
		// 				"hash": singleHash.Hash}}}).All(&results)

		// If we have results...
		if results != nil && len(results) > 0 {
			count = count + len(results)
			// For each hash found append it's cves to our CVEs instance
			for _, foundHash := range results {
				log.Logger.Infof("FoundHash: %#v", foundHash)
				cves.Append(foundHash.Cves)
			}
		}
	}
	log.Logger.Debugf("Found %d hashes", count)
	return cves
}

// DeepSearch checks one against the victims databse looking for matches.
func DeepSearch(c *gin.Context) {
	// Bind the request to a MultipleHashRequest instance
	requestedHash := types.MultipleHashRequest{}
	c.BindJSON(&requestedHash)

	cves := deepSearch(requestedHash)
	// Return the json to the requestor if we have cves
	if cves.Size() > 0 {
		c.JSON(200, cves)
		return
	}

	// Fall through to not found
	c.AbortWithStatus(404)
}

// Upload checks a provided package against the victims database
func Upload(c *gin.Context) {
	file, fileHeader, err := c.Request.FormFile("package")
	if err != nil {
		log.Logger.Infof("Error getting the file in upload: %s", err)
		// Bad Request
		c.AbortWithStatus(400)
	}
	defer file.Close()

	// Write the file out to the file system
	// TODO: Don't use the original name or /tmp
	out, err := os.Create("/tmp/" + fileHeader.Filename + ".test")
	defer out.Close()
	if err != nil {
		log.Logger.Fatal(err)
	}
	// Copy the content from the upload file to the file on disk
	fileSize, err := io.Copy(out, file)
	if err != nil {
		log.Logger.Fatal(err)
	}
	log.Logger.Infof("%s: %vk", fileHeader.Filename, int64(fileSize/1024))
	// TODO: Submit to hashing service
	// TODO: Retrieve response and store in requestedHash
	requestedHash := types.MultipleHashRequest{}
	requestedHash.Hashes = append(requestedHash.Hashes, types.SingleHashRequest{
		Hash: "a0a86214ea153fb07ff35ceec0848dd1703eae22de036a825efc8394e50f65e3044832f3b49cf7e45a39edc470bdf738abc36a3a78ca7df3a6e73c14eaef94a8",
	})
	// ----------
	// Search for hashes
	cves := deepSearch(requestedHash)
	if cves.Size() > 0 {
		c.JSON(200, cves)
		return
	}
	// Fall through to a 404
	c.AbortWithStatus(404)
}

// HashMounts mounts all hash related routes to a router
func HashMounts(router *gin.Engine) {
	router.POST("/search", SimpleSearch)
	router.POST("/deepsearch", DeepSearch)
	router.POST("/upload", Upload)
}