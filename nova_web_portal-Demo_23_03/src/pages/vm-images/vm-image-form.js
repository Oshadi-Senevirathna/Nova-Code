import { useState, useEffect } from 'react';
import serviceFactoryInstance from 'framework/services/service-factory';
import { ENTITY_NAME_SETTINGS, ENTITY_NAME_VM_IMAGE } from 'framework/caching/entity-cache';
import { Dialog, DialogTitle, DialogContent, Select } from '../../../node_modules/@mui/material/index';
// material-ui
import {
    Button,
    FormHelperText,
    Grid,
    InputLabel,
    Stack,
    Typography,
    OutlinedInput,
    Tooltip,
    IconButton,
    Box,
    LinearProgress,
    MenuItem
} from '@mui/material';
/* import { LinearProgress } from '../../../node_modules/@mui/material/index'; */
// third party
import { Formik } from 'formik';
// project import
import AnimateButton from 'components/@extended/AnimateButton';
import { DownloadOutlined } from '@ant-design/icons';
import config from '../../framework/configs/config.json';
// icons
// ============================|| FIREBASE - LOGIN ||============================ //

const VMImageForm = ({ formOpen, closeForm, UUID, setSuccessSnackbarMessage, setErrorSnackbarMessage }) => {
    const [initialValues, setInitialValues] = useState({
        instance_name: '',
        filename: '',
        category: ''
    });
    const [file, setFile] = useState();
    const [progress, setProgress] = useState();
    const [category, setCategory] = useState([]);

    useEffect(() => {
        const settingsSub = serviceFactoryInstance.dataLoaderService.dataSub(ENTITY_NAME_SETTINGS).subscribe((data) => {
            if (data) {
                data.forEach((setting) => {
                    if (setting.category === 'vm category') {
                        setCategory(setting.value);
                    }
                });
            }
        });

        return () => {
            settingsSub.unsubscribe();
        };
    }, [serviceFactoryInstance.cache]);

    useEffect(() => {
        if (UUID !== undefined) {
            //edit an existing instance
            serviceFactoryInstance.dataLoaderService.getInstance(UUID, ENTITY_NAME_VM_IMAGE).then((data) => {
                if (data.status) {
                    var instance = data.instance;
                    setFile(instance);
                    var temp = {};
                    temp['instance_name'] = instance.instance_name;
                    temp['filename'] = instance.filename;
                    temp['category'] = instance.category;
                    temp['UUID'] = instance.UUID;
                    setInitialValues(temp);
                }
            });
        }
    }, [UUID]);

    const cleanCloseForm = () => {
        closeForm();
        setProgress();
        setFile();
    };

    const onFileChange = (event) => {
        setFile(event.target.files[0]);
    };

    const setProgressFunction = (ongoingProgress) => {
        setProgress(ongoingProgress);
    };

    return (
        <>
            <Dialog style={{ width: '50%', margin: 'auto' }} open={formOpen} onClose={cleanCloseForm} fullWidth>
                <DialogTitle>VNF Image Form</DialogTitle>
                <DialogContent>
                    <Formik
                        enableReinitialize
                        initialValues={initialValues}
                        onSubmit={async (values, { setErrors, setSubmitting }) => {
                            setSubmitting(true);
                            if (!UUID) {
                                var tempValues = { ...values };
                                delete tempValues.filename;
                                const formData = new FormData();
                                formData.append('file', file);
                                serviceFactoryInstance.fileInteractionService
                                    .uploadFileToServer(ENTITY_NAME_VM_IMAGE, formData, file.name, setProgressFunction, tempValues)
                                    .then((data) => {
                                        if (data.status) {
                                            cleanCloseForm();
                                            setSubmitting(false);
                                            setSuccessSnackbarMessage('Successfully added image');
                                        } else {
                                            setErrors({ submit: data.reason });
                                            setSubmitting(false);
                                            setErrorSnackbarMessage('Failed to add image');
                                        }
                                    })
                                    .catch((reason) => {
                                        setErrors({ submit: reason });
                                        setSubmitting(false);
                                        setErrorSnackbarMessage('Failed to add image');
                                    });
                            } else {
                                serviceFactoryInstance.fileInteractionService
                                    .changeFileName(ENTITY_NAME_VM_IMAGE, values)
                                    .then((data) => {
                                        if (data.status) {
                                            cleanCloseForm();
                                            setSubmitting(false);
                                            setSuccessSnackbarMessage('Successfully edited image');
                                        } else {
                                            setErrors({ submit: data.reason });
                                            setSubmitting(false);
                                            setErrorSnackbarMessage('Failed to edit image');
                                        }
                                    })
                                    .catch((reason) => {
                                        setErrors({ submit: reason });
                                        setSubmitting(false);
                                        setErrorSnackbarMessage('Failed to edit image');
                                    });
                            }
                        }}
                    >
                        {({ errors, handleBlur, handleChange, handleSubmit, isSubmitting, touched, values, resetForm }) => (
                            <form noValidate onSubmit={handleSubmit}>
                                <Grid container spacing={3}>
                                    {UUID ? (
                                        <Grid item xs={12}>
                                            <Stack spacing={1}>
                                                <Stack direction="row" justifyContent="space-between">
                                                    <InputLabel htmlFor="vm-form-instance_name" style={{ alignSelf: 'center', flex: 2 }}>
                                                        VNF Name
                                                    </InputLabel>
                                                    <OutlinedInput
                                                        id="vm-form-instance_name"
                                                        type="text"
                                                        value={values.instance_name}
                                                        name="instance_name"
                                                        onBlur={handleBlur}
                                                        onChange={handleChange}
                                                        placeholder="Enter hostname"
                                                        style={{
                                                            backgroundColor: '#f5f5f5',
                                                            borderRadius: 5,
                                                            flex: 6
                                                        }}
                                                        error={Boolean(touched.instance_name && errors.instance_name)}
                                                    />
                                                    {touched.instance_name && errors.instance_name && (
                                                        <FormHelperText error id="standard-weight-helper-text-vm-form-instance_name">
                                                            {errors.instance_name}
                                                        </FormHelperText>
                                                    )}
                                                </Stack>
                                                <Stack direction="row" justifyContent="space-between">
                                                    <InputLabel htmlFor="vm-form-category" style={{ alignSelf: 'center', flex: 2 }}>
                                                        VNF Category
                                                    </InputLabel>
                                                    <Select
                                                        id="vm-form-category"
                                                        type="text"
                                                        value={values.category}
                                                        name="category"
                                                        onBlur={handleBlur}
                                                        onChange={handleChange}
                                                        placeholder="Enter category"
                                                        style={{
                                                            backgroundColor: '#f5f5f5',
                                                            borderRadius: 5,
                                                            flex: 6
                                                        }}
                                                        error={Boolean(touched.category && errors.category)}
                                                    >
                                                        {category
                                                            ? category.map(
                                                                  (option) =>
                                                                      option && (
                                                                          <MenuItem key={option} value={option}>
                                                                              {option}
                                                                          </MenuItem>
                                                                      )
                                                              )
                                                            : ''}
                                                    </Select>
                                                    {touched.category && errors.category && (
                                                        <FormHelperText error id="standard-weight-helper-text-vm-form-category">
                                                            {errors.category}
                                                        </FormHelperText>
                                                    )}
                                                </Stack>
                                                <Stack direction="row" justifyContent="space-between">
                                                    <InputLabel htmlFor="vm-form-filename" style={{ alignSelf: 'center', flex: 4 }}>
                                                        File Name
                                                    </InputLabel>
                                                    <OutlinedInput
                                                        id="vm-form-filename"
                                                        type="text"
                                                        value={values.filename}
                                                        name="filename"
                                                        onBlur={handleBlur}
                                                        onChange={handleChange}
                                                        placeholder="Enter filename"
                                                        style={{
                                                            backgroundColor: '#f5f5f5',
                                                            borderRadius: 5,
                                                            flex: 11
                                                        }}
                                                        error={Boolean(touched.filename && errors.filename)}
                                                    />
                                                    <a
                                                        style={{ alignSelf: 'center', flex: 1 }}
                                                        href={`${config.nodeURL}/download_file?entity_name=${ENTITY_NAME_VM_IMAGE}&UUID=${UUID}`}
                                                    >
                                                        <Tooltip title="Download">
                                                            <IconButton aria-label="download">
                                                                <DownloadOutlined style={{ alignSelf: 'center', fontSize: 25 }} />
                                                            </IconButton>
                                                        </Tooltip>
                                                    </a>
                                                    {touched.filename && errors.filename && (
                                                        <FormHelperText error id="standard-weight-helper-text-vm-form-filename">
                                                            {errors.filename}
                                                        </FormHelperText>
                                                    )}
                                                </Stack>
                                            </Stack>
                                        </Grid>
                                    ) : (
                                        <Grid item xs={12}>
                                            <Stack direction="row" justifyContent="space-between">
                                                <InputLabel htmlFor="vm-form-instance_name" style={{ alignSelf: 'center', flex: 1 }}>
                                                    VNF Name
                                                </InputLabel>
                                                <OutlinedInput
                                                    id="vm-form-instance_name"
                                                    type="text"
                                                    value={values.instance_name}
                                                    name="instance_name"
                                                    onBlur={handleBlur}
                                                    onChange={handleChange}
                                                    placeholder="Enter hostname"
                                                    style={{
                                                        backgroundColor: '#f5f5f5',
                                                        borderRadius: 5,
                                                        flex: 3
                                                    }}
                                                    error={Boolean(touched.instance_name && errors.instance_name)}
                                                />
                                                {touched.instance_name && errors.instance_name && (
                                                    <FormHelperText error id="standard-weight-helper-text-vm-form-instance_name">
                                                        {errors.instance_name}
                                                    </FormHelperText>
                                                )}
                                            </Stack>
                                            <Stack direction="row" justifyContent="space-between">
                                                <InputLabel htmlFor="vm-form-category" style={{ alignSelf: 'center', flex: 1 }}>
                                                    VNF Category
                                                </InputLabel>
                                                <Select
                                                    id="vm-form-category"
                                                    type="text"
                                                    value={values.category}
                                                    name="category"
                                                    onBlur={handleBlur}
                                                    onChange={handleChange}
                                                    placeholder="Enter category"
                                                    style={{
                                                        backgroundColor: '#f5f5f5',
                                                        borderRadius: 5,
                                                        flex: 3
                                                    }}
                                                    error={Boolean(touched.category && errors.category)}
                                                >
                                                    {category
                                                        ? category.map(
                                                              (option) =>
                                                                  option && (
                                                                      <MenuItem key={option} value={option}>
                                                                          {option}
                                                                      </MenuItem>
                                                                  )
                                                          )
                                                        : ''}
                                                </Select>
                                                {touched.category && errors.category && (
                                                    <FormHelperText error id="standard-weight-helper-text-vm-form-category">
                                                        {errors.category}
                                                    </FormHelperText>
                                                )}
                                            </Stack>
                                            <Stack direction="row" justifyContent="space-between" spacing={1} marginTop={1}>
                                                <InputLabel htmlFor="vm-form-image" style={{ alignSelf: 'center', flex: 1 }}>
                                                    VNF Image
                                                </InputLabel>
                                                <Box
                                                    sx={{
                                                        backgroundColor: '#f5f5f5',
                                                        borderRadius: '5px',
                                                        flex: 2
                                                    }}
                                                >
                                                    <Typography variant="subtitle1">{file && file.name ? file.name : ''}</Typography>
                                                </Box>

                                                <input
                                                    style={{ display: 'none' }}
                                                    id="raised-button-file"
                                                    type="file"
                                                    onChange={onFileChange}
                                                />
                                                <label htmlFor="raised-button-file">
                                                    <Button component="span" variant="contained" style={{ alignSelf: 'center', flex: 1 }}>
                                                        Select disk image
                                                    </Button>
                                                </label>
                                            </Stack>
                                            <Stack direction="row" justifyContent="space-between" spacing={1} marginTop={1}>
                                                <Grid item flex={1}>
                                                    {progress && (
                                                        <>
                                                            {progress === 0 ? (
                                                                <LinearProgress />
                                                            ) : (
                                                                <>
                                                                    <LinearProgress variant="determinate" value={progress} />
                                                                    {progress === 100 && !errors.submit && (
                                                                        <Typography style={{ color: 'success.main' }}>
                                                                            Upload complete!
                                                                        </Typography>
                                                                    )}
                                                                </>
                                                            )}
                                                        </>
                                                    )}
                                                </Grid>
                                            </Stack>
                                        </Grid>
                                    )}

                                    {errors.submit && (
                                        <Grid item xs={12}>
                                            <FormHelperText error>{errors.submit}</FormHelperText>
                                        </Grid>
                                    )}
                                    {!UUID ? (
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
                                                    {'Upload Image'}
                                                </Button>
                                            </AnimateButton>
                                        </Grid>
                                    ) : (
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
                                                    {'Save'}
                                                </Button>
                                            </AnimateButton>
                                        </Grid>
                                    )}
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

export default VMImageForm;
