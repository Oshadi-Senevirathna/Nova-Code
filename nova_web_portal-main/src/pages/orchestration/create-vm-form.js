import { useState, useEffect } from 'react';
import serviceFactoryInstance from 'framework/services/service-factory';
import { ENTITY_NAME_DEVICE, ENTITY_NAME_VM_TEMPLATES, ENTITY_NAME_FRONTEND_JOBS } from 'framework/caching/entity-cache';
import { Select, MenuItem } from '../../../node_modules/@mui/material/index';
// material-ui
import { Button, FormHelperText, Grid, InputLabel, Stack } from '@mui/material';
// third party
import { Formik } from 'formik';
// project import
import AnimateButton from 'components/@extended/AnimateButton';
// material-ui

// ============================|| FIREBASE - LOGIN ||============================ //

const CreateVMForm = ({ closeForm, setSuccessSnackbarMessage, setErrorSnackbarMessage }) => {
    const [initialValues, setInitialValues] = useState({
        device_id: '',
        template_id: ''
    });
    const [devices, setDevices] = useState();
    const [templates, setTemplates] = useState();

    useEffect(() => {
        const devicesSub = serviceFactoryInstance.dataLoaderService.dataSub(`${ENTITY_NAME_DEVICE}>summary`).subscribe((data) => {
            if (data) {
                setDevices(data);
            }
        });

        const templatesSub = serviceFactoryInstance.dataLoaderService.dataSub(`${ENTITY_NAME_VM_TEMPLATES}>summary`).subscribe((data) => {
            if (data) {
                setTemplates(data);
            }
        });

        return () => {
            devicesSub.unsubscribe();
            templatesSub.unsubscribe();
        };
    }, [serviceFactoryInstance.cache]);

    const cleanCloseForm = () => {
        closeForm();
        setInitialValues({
            device_id: '',
            template_id: ''
        });
    };

    return (
        <>
            <Formik
                enableReinitialize
                initialValues={initialValues}
                onSubmit={async (values, { setErrors, setSubmitting }) => {
                    var job = {};
                    job.job_name = 'Create VNF';
                    job.arguments = values;
                    setSubmitting(true);
                    serviceFactoryInstance.dataLoaderService
                        .addInstance(ENTITY_NAME_FRONTEND_JOBS, job)
                        .then((data) => {
                            if (data.status) {
                                setSubmitting(false);
                                setSuccessSnackbarMessage('Successfully added task');
                            } else {
                                setErrors({ submit: data.reason });
                                setSubmitting(false);
                                setErrorSnackbarMessage('Failed to add task');
                            }
                        })
                        .catch((reason) => {
                            setErrors({ submit: reason });
                            setSubmitting(false);
                            setErrorSnackbarMessage('Failed to add task');
                        });
                }}
            >
                {({ errors, handleBlur, handleChange, handleSubmit, isSubmitting, touched, values, resetForm }) => (
                    <form noValidate onSubmit={handleSubmit}>
                        <Grid container spacing={3}>
                            <Grid item xs={12}>
                                <Stack spacing={1}>
                                    <InputLabel htmlFor="create-vnf-form-device_id">Device</InputLabel>
                                    <Select
                                        id="create-vnf-form-device_id"
                                        type="text"
                                        value={values.device_id}
                                        name="device_id"
                                        onBlur={handleBlur}
                                        onChange={handleChange}
                                        placeholder="Select device"
                                        fullWidth
                                        error={Boolean(touched.device_id && errors.device_id)}
                                    >
                                        {devices
                                            ? devices.map(
                                                  (device) =>
                                                      device && (
                                                          <MenuItem key={device.UUID} value={device.UUID}>
                                                              {device.instance_name}
                                                          </MenuItem>
                                                      )
                                              )
                                            : ''}
                                    </Select>
                                    {touched.device_id && errors.device_id && (
                                        <FormHelperText error id="standard-weight-helper-text-create-vnf-form-device_id">
                                            {errors.device_id}
                                        </FormHelperText>
                                    )}
                                </Stack>
                            </Grid>
                            <Grid item xs={12}>
                                <Stack spacing={1}>
                                    <InputLabel htmlFor="create-vnf-form-template_id">Template</InputLabel>
                                    <Select
                                        id="create-vnf-form-template_id"
                                        type="text"
                                        value={values.template_id}
                                        name="template_id"
                                        onBlur={handleBlur}
                                        onChange={handleChange}
                                        placeholder="Select template"
                                        fullWidth
                                        error={Boolean(touched.template_id && errors.template_id)}
                                    >
                                        {templates
                                            ? templates.map(
                                                  (template) =>
                                                      template && (
                                                          <MenuItem key={template.UUID} value={template.UUID}>
                                                              {template.instance_name}
                                                          </MenuItem>
                                                      )
                                              )
                                            : ''}
                                    </Select>
                                    {touched.template_id && errors.template_id && (
                                        <FormHelperText error id="standard-weight-helper-text-create-vnf-form-template_id">
                                            {errors.template_id}
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
                                        {'Create'}
                                    </Button>
                                </AnimateButton>
                            </Grid>
                            <Grid item xs={12} md={6}>
                                <AnimateButton>
                                    <Button
                                        onClick={() => {
                                            resetForm();
                                            cleanCloseForm();
                                        }}
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
        </>
    );
};

export default CreateVMForm;
