import React from 'react';
import { useLocation } from 'react-router-dom';
import serviceFactoryInstance from 'framework/services/service-factory';
// material-ui
import {
    Button,
    FormHelperText,
    Grid,
    Link,
    IconButton,
    InputAdornment,
    InputLabel,
    OutlinedInput,
    Stack,
    Typography
} from '@mui/material';
// third party
import * as Yup from 'yup';
import { Formik } from 'formik';
// project import
import AnimateButton from 'components/@extended/AnimateButton';
// assets
import { EyeOutlined, EyeInvisibleOutlined } from '@ant-design/icons';

// ============================|| FIREBASE - LOGIN ||============================ //

const AuthResetPassword = () => {
    const [showPassword, setShowPassword] = React.useState(false);
    const [showRePassword, setShowRePassword] = React.useState(false);
    const [passwordReset, setShowPasswordReset] = React.useState(false);
    const location = useLocation();
    const handleClickShowPassword = () => {
        setShowPassword(!showPassword);
    };

    const handleClickShowRePassword = () => {
        setShowRePassword(!showRePassword);
    };

    const handleMouseDownPassword = (event) => {
        event.preventDefault();
    };

    const handleMouseDownRePassword = (event) => {
        event.preventDefault();
    };

    return (
        <>
            <Formik
                initialValues={{
                    password: '',
                    rePassword: '',
                    submit: null
                }}
                validationSchema={Yup.object().shape({
                    password: Yup.string().max(255).required('Password is required'),
                    rePassword: Yup.string().max(255).required('Re enter password is required')
                })}
                onSubmit={async (values, { setErrors, setStatus, setSubmitting }) => {
                    if (values.password !== values.rePassword) {
                        setErrors({ submit: 'Passwords do not match' });
                    } else {
                        const code = location.search.split('?code=')[1];
                        serviceFactoryInstance.authService.resetPassword(values.password, code, (data) => {
                            if (data.status) {
                                setShowPasswordReset(true);
                            } else {
                                setErrors({ submit: data.reason });
                            }
                        });
                        try {
                            setStatus({ success: false });
                            setSubmitting(false);
                        } catch (err) {
                            setStatus({ success: false });
                            setErrors({ submit: err.message });
                            setSubmitting(false);
                        }
                    }
                }}
            >
                {({ errors, handleBlur, handleChange, handleSubmit, isSubmitting, touched, values }) => (
                    <form noValidate onSubmit={handleSubmit}>
                        <Grid container spacing={3}>
                            <Grid item xs={12}>
                                <Stack spacing={1}>
                                    <InputLabel htmlFor="password-login">Password</InputLabel>
                                    <OutlinedInput
                                        fullWidth
                                        error={Boolean(touched.password && errors.password)}
                                        id="-password-login"
                                        type={showPassword ? 'text' : 'password'}
                                        value={values.password}
                                        name="password"
                                        onBlur={handleBlur}
                                        onChange={handleChange}
                                        endAdornment={
                                            <InputAdornment position="end">
                                                <IconButton
                                                    aria-label="toggle password visibility"
                                                    onClick={handleClickShowPassword}
                                                    onMouseDown={handleMouseDownPassword}
                                                    edge="end"
                                                    size="large"
                                                >
                                                    {showPassword ? <EyeOutlined /> : <EyeInvisibleOutlined />}
                                                </IconButton>
                                            </InputAdornment>
                                        }
                                        placeholder="Enter password"
                                    />
                                    {touched.password && errors.password && (
                                        <FormHelperText error id="standard-weight-helper-text-password-login">
                                            {errors.password}
                                        </FormHelperText>
                                    )}
                                </Stack>
                            </Grid>
                            <Grid item xs={12}>
                                <Stack spacing={1}>
                                    <InputLabel htmlFor="re-password-login">Re-enter password</InputLabel>
                                    <OutlinedInput
                                        fullWidth
                                        error={Boolean(touched.rePassword && errors.rePassword)}
                                        id="re-password-login"
                                        type={showRePassword ? 'text' : 'password'}
                                        value={values.rePassword}
                                        name="rePassword"
                                        onBlur={handleBlur}
                                        onChange={handleChange}
                                        endAdornment={
                                            <InputAdornment position="end">
                                                <IconButton
                                                    aria-label="toggle re enter password visibility"
                                                    onClick={handleClickShowRePassword}
                                                    onMouseDown={handleMouseDownRePassword}
                                                    edge="end"
                                                    size="large"
                                                >
                                                    {showRePassword ? <EyeOutlined /> : <EyeInvisibleOutlined />}
                                                </IconButton>
                                            </InputAdornment>
                                        }
                                        placeholder="Re enter password"
                                    />
                                    {touched.rePassword && errors.rePassword && (
                                        <FormHelperText error id="standard-weight-helper-text-re-password-login">
                                            {errors.rePassword}
                                        </FormHelperText>
                                    )}
                                </Stack>
                            </Grid>
                            {errors.submit && (
                                <Grid item xs={12}>
                                    <FormHelperText error>{errors.submit}</FormHelperText>
                                </Grid>
                            )}
                            <Grid item xs={12}>
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
                                        Reset password
                                    </Button>
                                </AnimateButton>
                            </Grid>
                            {passwordReset && (
                                <Grid item xs={12}>
                                    <Typography variant="body2">
                                        Your password was successfully reset, navigate to the login page to proceed with signing in to your
                                        account
                                    </Typography>
                                    <Link href="/" color="primary">
                                        Login
                                    </Link>
                                </Grid>
                            )}
                        </Grid>
                    </form>
                )}
            </Formik>
        </>
    );
};

export default AuthResetPassword;
