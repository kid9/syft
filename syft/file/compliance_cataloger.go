package file

import (
	"errors"
	"io"

	"github.com/google/licensecheck"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/source"
)

var errUncomplianceFile = errors.New("uncompliance file")

type ComplianceCataloger struct {
	skipFilesAboveSizeInBytes int64
}

func NewComplianceCataloger(skipFilesAboveSizeInBytes int64) (*ComplianceCataloger, error) {
	return &ComplianceCataloger{
		skipFilesAboveSizeInBytes: skipFilesAboveSizeInBytes,
	}, nil
}
func (i *ComplianceCataloger) Catalog(resolver source.FileResolver) (
	map[source.Coordinates]source.FileComplianceData, error) {
	results := make(map[source.Coordinates]source.FileComplianceData)
	var locations []source.Location

	locations = allRegularFiles(resolver)
	stage, prog := complianceCatalogingProcess(int64(len(locations)))
	for _, location := range locations {
		stage.Current = location.RealPath
		metadata, err := resolver.FileMetadataByLocation(location)
		if err != nil {
			return nil, err
		}
		if i.skipFilesAboveSizeInBytes > 0 && metadata.Size > i.skipFilesAboveSizeInBytes {
			continue
		}
		result, err := i.catalogLocation(resolver, location)

		if errors.Is(err, errUncomplianceFile) {
			continue
		}
		if internal.IsErrPathPermission(err) {
			log.Debugf("file compliance cataloger skipping %q: %+v", location.RealPath, err)
			continue
		}
		if err != nil {
			return nil, err
		}
		prog.N++
		results[location.Coordinates] = result
	}
	log.Debugf("file compliance cataloger processed %d files", prog.N)
	prog.SetCompleted()
	return results, nil
}

func (i *ComplianceCataloger) catalogLocation(resolver source.FileResolver, location source.Location) (
	source.FileComplianceData, error) {
	ret := source.FileComplianceData{}
	meta, err := resolver.FileMetadataByLocation(location)
	if err != nil {
		return ret, err
	}
	log.Debugf("scan file compliance in location: %s", location.RealPath)
	if meta.Type != source.RegularFile {
		return ret, errUncomplianceFile
	}
	contentReader, err := resolver.FileContentsByLocation(location)
	if err != nil {
		return ret, err
	}
	defer internal.CloseAndLogError(contentReader, location.VirtualPath)

	ret, err = ComplianceFromFile(contentReader)
	if err != nil {
		return ret, internal.ErrPath{Context: "compliance-cataloger", Path: location.RealPath, Err: err}
	}
	return ret, nil

}

func complianceCatalogingProcess(locations int64) (*progress.Stage, *progress.Manual) {
	stage := &progress.Stage{}
	prog := &progress.Manual{
		Total: locations,
	}

	bus.Publish(partybus.Event{
		Type: event.FileComplianceCatalogerStarted,
		Value: struct {
			progress.Stager
			progress.Progressable
		}{
			Stager:       progress.Stager(stage),
			Progressable: prog,
		},
	})

	return stage, prog
}

func ComplianceFromFile(closer io.ReadCloser) (source.FileComplianceData, error) {
	ret := source.FileComplianceData{}
	bytes, err := io.ReadAll(closer)
	if err != nil {
		return ret, err
	}
	cov := licensecheck.Scan(bytes)
	var (
		licenses       []string
		copyrightsText string
	)
	for _, match := range cov.Match {
		log.Debugf("File license matched: %s, match location %d:%d", match.ID, match.Start, match.End)
		licenses = append(licenses, match.ID)
	}
	return source.FileComplianceData{
		Licenses:       licenses,
		CopyrightsText: copyrightsText,
	}, nil
}
