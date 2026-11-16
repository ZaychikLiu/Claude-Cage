//go:build darwin && !no_vz

// SPDX-FileCopyrightText: Copyright The Lima Authors
// SPDX-License-Identifier: Apache-2.0

package vz

/*
#cgo darwin LDFLAGS: -framework CoreGraphics -framework CoreFoundation
#include <CoreGraphics/CoreGraphics.h>

static void cageHostDisplayMetrics(int64_t *pw, int64_t *ph, int64_t *lw, int64_t *lh) {
	*pw = 0; *ph = 0; *lw = 0; *lh = 0;
	CGDirectDisplayID id = CGMainDisplayID();
	if (id == kCGNullDirectDisplay) return;
	CGDisplayModeRef mode = CGDisplayCopyDisplayMode(id);
	if (!mode) return;
	*pw = (int64_t)CGDisplayModeGetPixelWidth(mode);
	*ph = (int64_t)CGDisplayModeGetPixelHeight(mode);
	*lw = (int64_t)CGDisplayModeGetWidth(mode);
	*lh = (int64_t)CGDisplayModeGetHeight(mode);
	CGDisplayModeRelease(mode);
}
*/
import "C"
import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/Code-Hex/vz/v3"
	"github.com/sirupsen/logrus"

	"github.com/lima-vm/lima/v2/pkg/limatype"
	"github.com/lima-vm/lima/v2/pkg/limatype/filenames"
	"github.com/lima-vm/lima/v2/pkg/osutil"
	"github.com/lima-vm/lima/v2/pkg/progressbar"
)

func getMacMachineIdentifier(identifier string) (machineIdentifier, error) {
	// Empty VzIdentifier can be created on cloning an instance.
	if st, err := os.Stat(identifier); err != nil || (st != nil && st.Size() == 0) {
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		machineIdentifier, err := vz.NewMacMachineIdentifier()
		if err != nil {
			return nil, err
		}
		err = os.WriteFile(identifier, machineIdentifier.DataRepresentation(), 0o666)
		if err != nil {
			return nil, err
		}
		return machineIdentifier, nil
	}
	return vz.NewMacMachineIdentifierWithDataPath(identifier)
}

func newMacPlatformConfiguration(inst *limatype.Instance) (vz.PlatformConfiguration, error) {
	identifierFile := filepath.Join(inst.Dir, filenames.VzIdentifier)
	machineIdentifier, err := getMacMachineIdentifier(identifierFile)
	if err != nil {
		return nil, err
	}

	var hwModelData []byte
	hwModelFile := filepath.Join(inst.Dir, filenames.VzHwModel)
	if osutil.FileExists(hwModelFile) {
		hwModelData, err = os.ReadFile(hwModelFile)
		if err != nil {
			return nil, err
		}
	} else {
		if err = ensureIPSW(inst.Dir); err != nil {
			return nil, err
		}
		ipsw, err := restoreImagePath(inst.Dir)
		if err != nil {
			return nil, err
		}
		ipswImage, err := vz.LoadMacOSRestoreImageFromPath(ipsw)
		if err != nil {
			return nil, err
		}
		if ipswImage == nil {
			return nil, fmt.Errorf("missing restore image for %q", ipsw)
		}
		requirements := ipswImage.MostFeaturefulSupportedConfiguration()
		if requirements == nil || requirements.MinimumSupportedCPUCount() == 0 {
			return nil, fmt.Errorf("IPSW %q has no configuration supported by this Mac", ipsw)
		}
		model := requirements.HardwareModel()
		if model == nil || !model.Supported() || len(model.DataRepresentation()) == 0 {
			return nil, fmt.Errorf("IPSW %q has no supported hardware model", ipsw)
		}
		hwModelData = model.DataRepresentation()
		if err = os.WriteFile(hwModelFile, hwModelData, 0o666); err != nil {
			return nil, err
		}
	}
	if len(hwModelData) == 0 {
		return nil, fmt.Errorf("empty macOS hardware model in %q", hwModelFile)
	}
	hwModel, err := vz.NewMacHardwareModelWithData(hwModelData)
	if err != nil {
		return nil, err
	}

	auxFile := filepath.Join(inst.Dir, filenames.VzAux)
	var auxOps []vz.NewMacAuxiliaryStorageOption
	if !osutil.FileExists(auxFile) {
		auxOps = append(auxOps, vz.WithCreatingMacAuxiliaryStorage(hwModel))
	}
	aux, err := vz.NewMacAuxiliaryStorage(auxFile, auxOps...)
	if err != nil {
		return nil, err
	}

	platformConfig, err := vz.NewMacPlatformConfiguration(
		vz.WithMacMachineIdentifier(machineIdentifier.(*vz.MacMachineIdentifier)),
		vz.WithMacHardwareModel(hwModel),
		vz.WithMacAuxiliaryStorage(aux),
	)
	if err != nil {
		return nil, err
	}
	return platformConfig, nil
}

func chooseMacOffscreenDisplay(pw, ph, lw, lh int64) (int64, int64, int64) {
	const (
		defaultWidth  int64 = 3840
		defaultHeight int64 = 2400
		retinaPPI     int64 = 220
		minWidth      int64 = 2560
		maxWidth      int64 = 3840
		maxHeight     int64 = 2560
	)
	if pw <= 0 || ph <= 0 || lw <= 0 || lh <= 0 {
		return defaultWidth, defaultHeight, retinaPPI
	}
	ratio := float64(lw) / float64(lh)
	if ratio < 1.2 || ratio > 2.6 {
		return defaultWidth, defaultHeight, retinaPPI
	}
	w := lw * 2
	if pw > w && pw <= maxWidth && ph <= maxHeight {
		w = pw
	}
	if w < minWidth {
		w = minWidth
	}
	if w > maxWidth {
		w = maxWidth
	}
	h := int64(math.Round(float64(w) / ratio))
	if h > maxHeight {
		h = maxHeight
		w = int64(math.Round(float64(h) * ratio))
	}
	w &^= 1
	h &^= 1
	if w < 1600 || h < 900 {
		return defaultWidth, defaultHeight, retinaPPI
	}
	return w, h, retinaPPI
}

func preferredMacOffscreenDisplay() (int64, int64, int64) {
	var pw, ph, lw, lh C.int64_t
	C.cageHostDisplayMetrics(&pw, &ph, &lw, &lh)
	return chooseMacOffscreenDisplay(int64(pw), int64(ph), int64(lw), int64(lh))
}

func newMacGraphicsDeviceConfiguration(x, y, pixelsPerInch int64) (vz.GraphicsDeviceConfiguration, error) {
	graphicsDeviceConfiguration, err := vz.NewMacGraphicsDeviceConfiguration()
	if err != nil {
		return nil, err
	}
	scanoutConfiguration, err := vz.NewMacGraphicsDisplayConfiguration(x, y, pixelsPerInch)
	if err != nil {
		return nil, err
	}
	graphicsDeviceConfiguration.SetDisplays(scanoutConfiguration)
	return graphicsDeviceConfiguration, nil
}

func newMacPointingDeviceConfiguration() (vz.PointingDeviceConfiguration, error) {
	return vz.NewMacTrackpadConfiguration()
}

func newMacKeyboardConfiguration() (vz.KeyboardConfiguration, error) {
	return vz.NewMacKeyboardConfiguration()
}

func newMacOSBootLoader() (vz.BootLoader, error) {
	return vz.NewMacOSBootLoader()
}

func installMacOS(ctx context.Context, vm *vz.VirtualMachine, ipsw string) error {
	installer, err := vz.NewMacOSInstaller(vm, ipsw)
	if err != nil {
		return err
	}

	const barResolution = 100
	bar, err := progressbar.New(barResolution)
	if err != nil {
		return err
	}
	bar.Start()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				logrus.WithError(ctx.Err()).Info("cancelling macOS installation")
				return
			case <-installer.Done():
				logrus.WithError(ctx.Err()).Info("macOS installer exited")
				bar.SetCurrent(barResolution)
				return
			case <-ticker.C:
				progress := installer.FractionCompleted() * barResolution
				bar.SetCurrent(int64(progress))
			}
		}
	}()

	err = installer.Install(ctx)
	bar.Finish()
	if err != nil {
		return err
	}

	stopped, err := vm.RequestStop()
	if err != nil {
		return fmt.Errorf("failed to stop VM after installation: %w", err)
	}
	if !stopped {
		logrus.WithError(err).Warn("VM did not stop after installation")
		if err = vm.Stop(); err != nil {
			return fmt.Errorf("failed to force stop VM after installation: %w", err)
		}
	}
	return nil
}
