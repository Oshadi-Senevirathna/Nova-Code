import { useEffect, useState } from 'react';
import serviceFactoryInstance from 'framework/services/service-factory';
import { ENTITY_NAME_VM_CONFIGS, ENTITY_NAME_VM_IMAGE } from 'framework/caching/entity-cache';
import { Dialog, DialogTitle, DialogContent, Select } from '../../../node_modules/@mui/material/index';
// material-ui
import { Button, FormHelperText, Grid, InputLabel, OutlinedInput, Stack, MenuItem } from '@mui/material';
// third party
import { Formik } from 'formik';
// project import
import AnimateButton from 'components/@extended/AnimateButton';

// ============================|| FIREBASE - LOGIN ||============================ //

const VMConfigsForm = ({ formOpen, closeForm, UUID, setSuccessSnackbarMessage, setErrorSnackbarMessage, vmTemplate }) => {
    const [initialValues, setInitialValues] = useState({
        vm_image_id: '',
        memory: '',
        vcpu: ''
    });
    const [loading, setLoading] = useState(false);
    const [vmImages, setVmImages] = useState();

    useEffect(() => {
        if (UUID !== undefined) {
            //edit an existing instance
            serviceFactoryInstance.dataLoaderService.getInstance(UUID, ENTITY_NAME_VM_CONFIGS).then((data) => {
                if (data.status) {
                    var temp = {};
                    temp['vm_image_id'] = data.instance.vm_image_id;
                    temp['memory'] = data.instance.memory;
                    temp['vcpu'] = data.instance.vcpu;
                    temp['UUID'] = data.instance.UUID;
                    setInitialValues(temp);
                }
            });
        }
    }, [UUID]);

    useEffect(() => {
        const imagesSub = serviceFactoryInstance.dataLoaderService.dataSub(`${ENTITY_NAME_VM_IMAGE}>summary`).subscribe((data) => {
            if (data) {
                setVmImages(data);
            }
        });
        return () => {
            imagesSub.unsubscribe();
        };
    }, [serviceFactoryInstance.cache]);

    const cleanCloseForm = () => {
        closeForm();
        setInitialValues({
            vm_image_id: '',
            memory: '',
            vcpu: ''
        });
    };

    return (
        <>
            <Dialog style={{ width: '50%', margin: 'auto' }} open={formOpen} onClose={cleanCloseForm} fullWidth>
                <DialogTitle>VNF Config Form</DialogTitle>
                <DialogContent>
                    <Formik
                        enableReinitialize
                        initialValues={initialValues}
                        onSubmit={async (values, { setErrors, setSubmitting }) => {
                            setSubmitting(true);
                            values.vm_template_id = vmTemplate;
                            UUID
                                ? serviceFactoryInstance.dataLoaderService
                                      .updateInstance(ENTITY_NAME_VM_CONFIGS, values)
                                      .then((data) => {
                                          if (data.status) {
                                              cleanCloseForm();
                                              setSubmitting(false);

                                              setSuccessSnackbarMessage('Successfully edited config');
                                          } else {
                                              setErrors({ submit: data.reason });
                                              setSubmitting(false);
                                              setErrorSnackbarMessage('Editing config failed');
                                          }
                                      })
                                      .catch((reason) => {
                                          setErrors({ submit: reason });
                                          setSubmitting(false);
                                          setErrorSnackbarMessage('Editing config failed');
                                      })
                                : serviceFactoryInstance.dataLoaderService
                                      .addInstance(ENTITY_NAME_VM_CONFIGS, values)
                                      .then((data) => {
                                          if (data.status) {
                                              cleanCloseForm();
                                              setSubmitting(false);
                                              setSuccessSnackbarMessage('Successfully added config');
                                          } else {
                                              setErrors({ submit: data.reason });
                                              setSubmitting(false);
                                              setErrorSnackbarMessage('Adding config failed');
                                          }
                                      })
                                      .catch((reason) => {
                                          setErrors({ submit: reason });
                                          setSubmitting(false);
                                          setErrorSnackbarMessage('Adding config failed');
                                      });
                        }}
                    >
                        {({ errors, handleBlur, handleChange, handleSubmit, isSubmitting, touched, values, resetForm }) => (
                            <form noValidate onSubmit={handleSubmit}>
                                <Grid container spacing={3}>
                                    <Grid item xs={12}>
                                        <Stack spacing={1}>
                                            <InputLabel htmlFor="vm-configs-form-vm_image_id">VNF Image</InputLabel>
                                            <Select
                                                id="vm-configs-form-vm_image_id"
                                                type="text"
                                                value={values.vm_image_id}
                                                name="vm_image_id"
                                                onBlur={handleBlur}
                                                onChange={handleChange}
                                                placeholder="Select vnf image"
                                                fullWidth
                                                error={Boolean(touched.vm_image_id && errors.vm_image_id)}
                                            >
                                                {vmImages
                                                    ? vmImages.map(
                                                          (option) =>
                                                              option && (
                                                                  <MenuItem key={option.UUID} value={option.UUID}>
                                                                      {option.instance_name}
                                                                  </MenuItem>
                                                              )
                                                      )
                                                    : ''}
                                            </Select>
                                            {touched.vm_image_id && errors.vm_image_id && (
                                                <FormHelperText error id="standard-weight-helper-text-vm-configs-form-vm_image_id">
                                                    {errors.vm_image_id}
                                                </FormHelperText>
                                            )}
                                        </Stack>
                                    </Grid>
                                    <Grid item xs={12}>
                                        <Stack spacing={1}>
                                            <InputLabel htmlFor="vm-configs-form-memory">Memory</InputLabel>
                                            <OutlinedInput
                                                id="vm-configs-form-memory"
                                                type="text"
                                                value={values.memory}
                                                name="memory"
                                                onBlur={handleBlur}
                                                onChange={handleChange}
                                                placeholder="Enter memory"
                                                fullWidth
                                                error={Boolean(touched.memory && errors.memory)}
                                            />
                                            {touched.memory && errors.memory && (
                                                <FormHelperText error id="standard-weight-helper-text-vm-configs-form-memory">
                                                    {errors.memory}
                                                </FormHelperText>
                                            )}
                                        </Stack>
                                    </Grid>
                                    <Grid item xs={12}>
                                        <Stack spacing={1}>
                                            <InputLabel htmlFor="vm-configs-form-vcpu">vCPU</InputLabel>
                                            <OutlinedInput
                                                id="vm-configs-form-vcpu"
                                                type="text"
                                                value={values.vcpu}
                                                name="vcpu"
                                                onBlur={handleBlur}
                                                onChange={handleChange}
                                                placeholder="Enter vcpu"
                                                fullWidth
                                                error={Boolean(touched.vcpu && errors.vcpu)}
                                            />
                                            {touched.vcpu && errors.vcpu && (
                                                <FormHelperText error id="standard-weight-helper-text-vm-configs-form-vcpu">
                                                    {errors.vcpu}
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
                                                {!UUID ? 'Add Config' : 'Save'}
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

export default VMConfigsForm;
