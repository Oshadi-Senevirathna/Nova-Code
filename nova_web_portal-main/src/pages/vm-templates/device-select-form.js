import { useEffect, useState } from 'react';
import serviceFactoryInstance from 'framework/services/service-factory';
import { ENTITY_NAME_DEVICE } from 'framework/caching/entity-cache';
import { Dialog, DialogTitle, DialogContent } from '../../../node_modules/@mui/material/index';
// material-ui
import { Button, FormHelperText, Grid, InputLabel, Stack } from '@mui/material';
// third party
import { Formik } from 'formik';
// project import
import AnimateButton from 'components/@extended/AnimateButton';
import Multiselect from '../../../node_modules/multiselect-react-dropdown/dist/index';
import { ENTITY_NAME_FRONTEND_JOBS } from 'framework/caching/entity-cache';

// ============================|| FIREBASE - LOGIN ||============================ //

const DeviceSelectForm = ({ formOpen, closeForm, setSuccessSnackbarMessage, setErrorSnackbarMessage, vmTemplate }) => {
    const [initialValues, setInitialValues] = useState({
        devices: []
    });
    const [loading, setLoading] = useState(false);
    const [devices, setdevices] = useState();
    const [selectedDevices, setSelectedDevices] = useState([]);

    useEffect(() => {
        const devicesSub = serviceFactoryInstance.dataLoaderService.dataSub(`${ENTITY_NAME_DEVICE}>summary`).subscribe((data) => {
            if (data) {
                setdevices(data);
            }
        });
        return () => {
            devicesSub.unsubscribe();
        };
    }, [serviceFactoryInstance.cache]);

    const cleanCloseForm = () => {
        setInitialValues({
            devices: []
        });
        setSelectedDevices([]);
        closeForm();
    };

    const onSelect = (selectedList, selectedItem) => {
        setSelectedDevices([...selectedList]);
        console.log(selectedList);
    };

    const onRemove = (selectedList, removedItem) => {
        var selectedListTemp = [...selectedList];
        const position = selectedList.indexOf(removedItem);
        if (position !== -1) {
            selectedListTemp.splice(position, 1);
        }
        setSelectedDevices(selectedListTemp);
    };

    return (
        <>
            <Dialog style={{ width: '50%', margin: 'auto' }} open={formOpen} onClose={cleanCloseForm} fullWidth>
                <DialogTitle>Device Select Form</DialogTitle>
                <DialogContent>
                    <Formik
                        enableReinitialize
                        initialValues={{ devices: selectedDevices }}
                        onSubmit={async (values, { setErrors, setSubmitting }) => {
                            var job = {};
                            job.job_name = 'Create VNF';
                            var args = {};
                            args.devices = values.selectedDevices;
                            args.template = vmTemplate;
                            job.arguments = args;
                            setSubmitting(true);
                            serviceFactoryInstance.dataLoaderService
                                .addInstance(ENTITY_NAME_FRONTEND_JOBS, job)
                                .then((data) => {
                                    if (data.status) {
                                        cleanCloseForm();
                                        setSubmitting(false);
                                        setSuccessSnackbarMessage('Successfully added the template');
                                    } else {
                                        setErrors({ submit: data.reason });
                                        setSubmitting(false);
                                        setErrorSnackbarMessage('Failed to add the template');
                                    }
                                })
                                .catch((reason) => {
                                    setErrors({ submit: reason });
                                    setSubmitting(false);
                                    setErrorSnackbarMessage('Failed to add the template');
                                });
                        }}
                    >
                        {({ errors, handleBlur, handleChange, handleSubmit, isSubmitting, touched, values, resetForm }) => (
                            <form noValidate onSubmit={handleSubmit}>
                                <Grid container spacing={3}>
                                    <Grid item xs={12}>
                                        <Stack spacing={1} style={{ height: 300 }}>
                                            <InputLabel htmlFor="device-select-form-devices">Select devices to apply template</InputLabel>
                                            <Multiselect
                                                showCheckbox={true}
                                                options={devices} // Options to display in the dropdown
                                                selectedValues={selectedDevices} // Preselected value to persist in dropdown
                                                onSelect={onSelect} // Function will trigger on select event
                                                onRemove={onRemove} // Function will trigger on remove event
                                                displayValue="instance_name" // Property name to display in the dropdown options
                                            />
                                            {touched.devices && errors.devices && (
                                                <FormHelperText error id="standard-weight-helper-text-device-select-form-devices">
                                                    {errors.devices}
                                                </FormHelperText>
                                            )}
                                        </Stack>
                                    </Grid>

                                    {errors.submit && (
                                        <Grid item xs={12}>
                                            <FormHelperText error>{errors.submit}</FormHelperText>
                                        </Grid>
                                    )}
                                    <Grid item xs={12} md={6}>
                                        <AnimateButton>
                                            <Button
                                                disableElevation
                                                disabled={isSubmitting}
                                                fullWidth
                                                size="large"
                                                type="submit"
                                                variant="contained"
                                                color="primary"
                                            >
                                                Apply Template
                                            </Button>
                                        </AnimateButton>
                                    </Grid>
                                    <Grid item xs={12} md={6}>
                                        <AnimateButton>
                                            <Button
                                                onClick={cleanCloseForm}
                                                disableElevation
                                                fullWidth
                                                size="large"
                                                variant="contained"
                                                color="primary"
                                                type="button"
                                            >
                                                Cancel
                                            </Button>
                                        </AnimateButton>
                                    </Grid>
                                </Grid>
                            </form>
                        )}
                    </Formik>
                </DialogContent>
            </Dialog>
        </>
    );
};

export default DeviceSelectForm;
