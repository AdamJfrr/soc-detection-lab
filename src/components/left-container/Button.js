import classes from './Button.module.css';
const Button = (props) => {
  const clickHandler = () => {
     props.forwardHandler(props.id,props.label)
  }
  return (
    <button onClick={clickHandler} className={classes.button} id={props.id}>{props.label}</button>
  )
}
export default Button;
